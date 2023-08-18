// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package mgmysql

import (
    "bytes"
    "context"
    "encoding/json"
    "errors"
    "fmt"
    "github.com/hashicorp/go-hclog"
    "io/ioutil"
    "os"
    "strings"
    "time"

    "github.com/hashicorp/vault/sdk/database/dbplugin/v5"
    "github.com/hashicorp/vault/sdk/database/helper/credsutil"
)

const (
    mysqlTypeName        = "mgtv_mysql"
    defaultRedisUserRule = `["~*", "+@read"]`
    defaultTimeout       = 20000 * time.Millisecond
    maxKeyLength         = 13
    mysqlToken           = "mysql_token"
    addUser              = "AddUser"
    delUser              = "VaultDelUser"
    vaultMysqlDb         = "vault_mysql_db"
)

type MysqlCreateRequest struct {
    action    string
    cid       string
    token     string
    dbname    string
    priv      string
    username  string
    password  string
    iplist    string
    approle   string
    isoffline string
}

var _ dbplugin.Database = (*MgtvMysql)(nil)

// Type that combines the custom plugins Redis database connection configuration options and the Vault CredentialsProducer
// used for generating user information for the Redis database.
type MgtvMysql struct {
    *mgtvMysqlConnectionProducer
}

// New implements builtinplugins.BuiltinFactory
func New() (interface{}, error) {
    db := new()
    // Wrap the plugin with middleware to sanitize errors
    dbType := dbplugin.NewDatabaseErrorSanitizerMiddleware(db, db.secretValues)
    return dbType, nil
}

func new() *MgtvMysql {
    connProducer := &mgtvMysqlConnectionProducer{}
    connProducer.Type = mysqlTypeName

    return &MgtvMysql{
        mgtvMysqlConnectionProducer: connProducer,
    }
}

func (c *MgtvMysql) Initialize(ctx context.Context, req dbplugin.InitializeRequest) (dbplugin.InitializeResponse, error) {
    err := c.mgtvMysqlConnectionProducer.Initialize(ctx, req.Config, req.VerifyConnection)
    if err != nil {
        return dbplugin.InitializeResponse{}, err
    }
    resp := dbplugin.InitializeResponse{
        Config: req.Config,
    }
    return resp, nil
}

func nameTrunc(str string, l int) string {
    switch {
    case l > 0:
        if l > len(str) {
            return str
        }
        return str[:l]
    case l == 0:
        return str
    default:
        return ""
    }
}

func (c *MgtvMysql) NewUser(ctx context.Context, req dbplugin.NewUserRequest) (dbplugin.NewUserResponse, error) {
    // Grab the lock
    c.Lock()
    defer c.Unlock()
    username, err := credsutil.GenerateUsername(credsutil.DisplayName("", maxKeyLength))
    username = nameTrunc(username, maxKeyLength)
    if err != nil {
        return dbplugin.NewUserResponse{}, fmt.Errorf("failed to generate username: %w", err)
    }
    username = strings.ToUpper(username)

    statements := req.Statements.Commands
    token := os.Getenv(mysqlToken)
    if len(token) == 0 {
        return dbplugin.NewUserResponse{}, errors.New("not exist mysql token")
    }

    if len(statements) > 1 {
        return dbplugin.NewUserResponse{}, errors.New("a maximum of one create_statement is supported")
    }
    if len(statements) == 0 {
        return dbplugin.NewUserResponse{}, errors.New("create_statement is empty")
    }
    statement := statements[0]
    body := make(map[string]interface{})
    err = json.Unmarshal([]byte(statement), &body)
    if err != nil {
        return dbplugin.NewUserResponse{}, err
    }
    if body["priv"] != nil && body["priv"] != 0 && body["priv"] != "0" {
        username = fmt.Sprintf("%s_%s", username, "rw")
    } else {
        username = fmt.Sprintf("%s_%s", username, "r")
    }
    body["username"] = username
    body["password"] = req.Password
    body["action"] = addUser
    body["token"] = token
    marshal, err := json.Marshal(body)
    if err != nil {
        return dbplugin.NewUserResponse{}, err
    }
    logger := hclog.New(&hclog.LoggerOptions{})
    logger.Info("request db create user body:",marshal)
    response, err := c.httpClient.Post(c.ConnectionURL, "application/json", bytes.NewReader(marshal))
    if err != nil {
        return dbplugin.NewUserResponse{}, fmt.Errorf("invoke db create user: %s failed: %s", username, err)
    }
    if response.StatusCode != 200 {
        return dbplugin.NewUserResponse{}, fmt.Errorf("invoke db create user:%s failed: http statusCode: %s", username,response.StatusCode)
    }
    resp_body, err := ioutil.ReadAll(response.Body)
    if err != nil {
        return dbplugin.NewUserResponse{}, fmt.Errorf("invoke db create user:%s failed: %s",username, err)
    }
    result := make(map[string]interface{})
    err = json.Unmarshal(resp_body, &result)
    if err != nil {
        return dbplugin.NewUserResponse{}, fmt.Errorf("invoke db create user:%s failed: %s",username, err)
    }
    status := result["status"]
    if status.(float64) != 0 {
        return dbplugin.NewUserResponse{}, fmt.Errorf("invoke db create user:%s failed: %s",username, result["error"])
    }

    resp := dbplugin.NewUserResponse{
        Username: username,
    }
    return resp, nil
}

func (c *MgtvMysql) UpdateUser(ctx context.Context, req dbplugin.UpdateUserRequest) (dbplugin.UpdateUserResponse, error) {
    if req.Password != nil {
        err := c.changeUserPassword(ctx, req.Username, req.Password.NewPassword)
        return dbplugin.UpdateUserResponse{}, err
    }
    return dbplugin.UpdateUserResponse{}, nil
}

func (c *MgtvMysql) DeleteUser(ctx context.Context, req dbplugin.DeleteUserRequest) (dbplugin.DeleteUserResponse, error) {
    c.Lock()
    defer c.Unlock()

    username := req.Username
    if len(req.Statements.Commands) == 0 {
        return dbplugin.DeleteUserResponse{}, fmt.Errorf("revocation % failed,Revocation Statements is empty", username)
    }
    revocation_str := req.Statements.Commands[0]
    //revocationJson, e := json.Marshal(revocation_str)
    //if e != nil {
    //    return dbplugin.DeleteUserResponse{}, e
    //}
    revocation := make(map[string]interface{})
    err := json.Unmarshal([]byte(revocation_str), &revocation)
    if err != nil {
        return dbplugin.DeleteUserResponse{}, err
    }
    revocation["action"] = delUser
    revocation["token"] = os.Getenv(mysqlToken)
    revocation["username"] = username
    body, e := json.Marshal(revocation)
    if e != nil {
        return dbplugin.DeleteUserResponse{}, e
    }
    response, err := c.httpClient.Post(c.ConnectionURL, "application/json", bytes.NewReader(body))
    if err != nil {
        return dbplugin.DeleteUserResponse{}, err
    }
    if response.StatusCode != 200 {
        return dbplugin.DeleteUserResponse{}, fmt.Errorf("delete user failed: http statusCode: %s", response.StatusCode)
    }
    resp_body, err := ioutil.ReadAll(response.Body)
    if err != nil {
        return dbplugin.DeleteUserResponse{}, fmt.Errorf("delete user failed: %s", err)
    }
    result := make(map[string]interface{})
    err = json.Unmarshal(resp_body, &result)
    if err != nil {
        return dbplugin.DeleteUserResponse{}, fmt.Errorf("delete user failed: %s", err)
    }
    status := result["status"]
    if status.(float64) != 0  {
        return dbplugin.DeleteUserResponse{}, fmt.Errorf("delete user failed: %s", result["error"])
    }
    return dbplugin.DeleteUserResponse{}, nil
}

func (c *MgtvMysql) changeUserPassword(ctx context.Context, username, password string) error {
    // nothing to do
    return nil
}

func (c *MgtvMysql) Type() (string, error) {
    return mysqlTypeName, nil
}

// Close terminates the database connection with locking
func (c *mgtvMysqlConnectionProducer) Close() error {
    // nothing to do
    return nil
}

func (c *mgtvMysqlConnectionProducer) Connection(ctx context.Context) (interface{}, error) {
    // nothing to do
    return nil, nil
}
