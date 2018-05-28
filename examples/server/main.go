package main

import (
	"fmt"
	"git.cloud.top/vgate/liblicense"
	"io/ioutil"
	"os"
)

//定义RSA全局公私密钥
var privateKey []byte

//初始化RSA公私钥
func init() {

	var err error
	//vgate 私钥
	privateKey, err = ioutil.ReadFile("private.pem")
	if err != nil {
		os.Exit(-1)
	}

}

func main() {
	var cipherFile string = "vgate_info.conf"
	var licenseFile string = "license"

	var data *license.LicenseControl
	//读取vgate密文
	EncText, err := data.ReadFile(cipherFile)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	//解密vgate信息
	vgateText, err := license.DecLicenseSer(string(EncText), privateKey)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("vgateText ls \n", vgateText)

	//读取license明文
	licenseText, err := data.ReadFile(licenseFile)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	//加密license信息
	encLicText, err := license.EncLicenseSer(vgateText, string(licenseText), privateKey)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Println("encLicText ls \n", encLicText)

	return

}
