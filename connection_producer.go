// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package mgmysql

import (
    "context"
    "database/sql"
    "net"
    "net/http"
    "os"
    "sync"
    "time"

    "github.com/mitchellh/mapstructure"
)

type mgtvMysqlConnectionProducer struct {
    ConnectionURL   string `json:"connection_url"          mapstructure:"connection_url"          structs:"connection_url"`
    Type            string
    RawConfig       map[string]interface{}
    Timeout         time.Duration `json:"timeout" mapstructure:"timeout" structs:"timeout"`
    KeepAlive       time.Duration `json:"keep_alive" mapstructure:"keep_alive" structs:"keep_alive"`
    IdleConnTimeout time.Duration `json:"idle_conn_timeout" mapstructure:"idle_conn_timeout" structs:"idle_conn_timeout"`
    MaxIdleConns    int           `json:"max_idle_conns" mapstructure:"max_idle_conns" structs:"max_idle_conns"`
    httpClient      http.Client
    Initialized     bool
    db              *sql.DB
    sync.Mutex
}

func (c *mgtvMysqlConnectionProducer) secretValues() map[string]string {
    return map[string]string{
    }
}

func (c *mgtvMysqlConnectionProducer) Init(ctx context.Context, initConfig map[string]interface{}, verifyConnection bool) (saveConfig map[string]interface{}, err error) {
    c.Lock()
    defer c.Unlock()

    c.RawConfig = initConfig

    decoderConfig := &mapstructure.DecoderConfig{
        Result:           c,
        WeaklyTypedInput: true,
        TagName:          "json",
    }

    decoder, err := mapstructure.NewDecoder(decoderConfig)
    if err != nil {
        return nil, err
    }

    err = decoder.Decode(initConfig)
    if err != nil {
        return nil, err
    }

    //if len(c.ConnectionURL) == 0 {
    c.ConnectionURL = os.Getenv(vaultMysqlDb)
    //}

    c.Initialized = true

    return initConfig, nil
}

func (c *mgtvMysqlConnectionProducer) Initialize(ctx context.Context, config map[string]interface{}, verifyConnection bool) error {
    _, err := c.Init(ctx, config, verifyConnection)
    c.initHttpConnPool()
    return err
}

func (c *mgtvMysqlConnectionProducer) initHttpConnPool() {
    c.httpClient = http.Client{
        Timeout: c.Timeout * time.Second,
        Transport: &http.Transport{
            DialContext: (&net.Dialer{
                Timeout:   c.Timeout * time.Second,
                KeepAlive: c.KeepAlive * time.Second,
            }).DialContext,
            MaxIdleConns:    c.MaxIdleConns,
            IdleConnTimeout: c.IdleConnTimeout * time.Second,
        },
    }
}
