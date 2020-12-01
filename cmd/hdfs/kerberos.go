package main

import (
	"fmt"
	"gopkg.in/jcmturner/gokrb5.v5/keytab"
	"os"
	"os/user"
	"strings"

	krb "gopkg.in/jcmturner/gokrb5.v5/client"
	"gopkg.in/jcmturner/gokrb5.v5/config"
	"gopkg.in/jcmturner/gokrb5.v5/credentials"
)

// TODO: Write a kerberos_windows.go and move this to kerberos_unix.go. This
// assumes MIT kerberos on unix.

func getKerberosClient() (*krb.Client, error) {
	configPath := os.Getenv("KRB5_CONFIG")
	if configPath == "" {
		configPath = "/etc/krb5.conf"
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, err
	}

	// Determine the ccache location from the environment, falling back to the
	// default location.
	ccachePath := os.Getenv("KRB5CCNAME")
	if strings.Contains(ccachePath, ":") {
		if strings.HasPrefix(ccachePath, "FILE:") {
			ccachePath = strings.SplitN(ccachePath, ":", 2)[1]
		} else {
			return nil, fmt.Errorf("unusable ccache: %s", ccachePath)
		}
	} else if ccachePath == "" {
		u, err := user.Current()
		if err != nil {
			return nil, err
		}

		ccachePath = fmt.Sprintf("/tmp/krb5cc_%s", u.Uid)
	}

	ccache, err := credentials.LoadCCache(ccachePath)
	if err != nil {
		return nil, err
	}

	client, err := krb.NewClientFromCCache(ccache)
	if err != nil {
		return nil, err
	}

	return client.WithConfig(cfg), nil
}

func getKerberosClientFromKeytab() (*krb.Client, error) {
	configPath := os.Getenv("KRB5_CONFIG")
	if configPath == "" {
		configPath = "/etc/krb5.conf"
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, err
	}

	// Determine the ccache location from the environment, falling back to the
	// default location.
	ccachePath := os.Getenv("KRB5CCNAME")
	if strings.Contains(ccachePath, ":") {
		if strings.HasPrefix(ccachePath, "FILE:") {
			ccachePath = strings.SplitN(ccachePath, ":", 2)[1]
		} else {
			return nil, fmt.Errorf("unusable ccache: %s", ccachePath)
		}
	} else if ccachePath == "" {
		u, err := user.Current()
		if err != nil {
			return nil, err
		}

		ccachePath = fmt.Sprintf("/tmp/krb5cc_%s", u.Uid)
	}

	//keytabPath := os.Getenv("/task_runtime/amp_turi_trove_ml.app.turi.amp-trove-hdfs.keytab")
	keytabPath := "/task_runtime/amp_turi_trove_ml.app.turi.amp-trove-hdfs.keytab"

	kt, err := keytab.Load(keytabPath)
	fmt.Printf("key lab %+v, %+v\n", kt, kt.Entries)
	client := krb.NewClientWithKeytab("amp_turi_trove_ml/app.turi.amp-trove-hdfs", "PIE.APPLE.COM", kt)

	client.WithConfig(cfg)

	err = client.Login()
	if err != nil {
		fmt.Printf("Error while logging %+v\n", err)
		return nil, err
	}
	//ccache, err := credentials.LoadCCache(ccachePath)
	//if err != nil {
	//	return nil, err
	//}
	//
	//client, err := krb.NewClientFromCCache(ccache)
	//if err != nil {
	//	return nil, err
	//}

	return &client, nil
}
