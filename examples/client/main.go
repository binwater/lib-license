package main

import (
	"fmt"
	"git.cloud.top/vgate/liblicense"
	//"io/ioutil"
)

func main() {
	/*
		var KeyLen string = "1024"

		//服务端 公钥
		publicKey, err := ioutil.ReadFile("/tos/etc/public.pem")
		if err != nil {
			return
		}

		//产生机器码
		machine_code, err := license.GenerateInfoCli(KeyLen, publicKey)
		if err != nil {
			fmt.Println(err.Error())
		}
		fmt.Println(machine_code)
	*/
	var licenseFileName string = "enc_file.conf"

	var data *license.LicenseControl //声明一个总license控制对象的指针
	//读取密文
	EncText, err := data.ReadFile(licenseFileName)
	if err != nil {
		return
	}

	dec_license, err := license.DecLicenseCli(string(EncText))
	if err != nil {
		fmt.Println("\n\n\n", err.Error())
	}
	fmt.Println(dec_license)

	return
}
