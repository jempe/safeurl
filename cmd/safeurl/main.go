package main

import (
	"fmt"
	"github.com/jempe/safeurl"
	"github.com/spf13/viper"
	"os"
)

func main() {
	url := os.Args[1]

	viper.SetConfigName("config")
	viper.AddConfigPath("$HOME/.safeurl")
	viper.AddConfigPath(".")
	err := viper.ReadInConfig()

	checkErr(err)

	safeurl.SetAPIKey(viper.GetString("api_key"))
	isSafe, err := safeurl.IsSafeURL(url)
	checkErr(err)

	message := "is a safe URL"

	if !isSafe {
		message = "is not a safe URL"
	}

	fmt.Println(url, message)

}

func checkErr(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
