package license

import (
	"crypto"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"testing"
)

//==============================================================================
/*
 *测试文件格式头对象的方法
 */
//==============================================================================
//测试产出buf头函数功能
func TestGenerateHeadBuf(test *testing.T) {

	var vhead *Head
	var flag int
	a := []byte{1, 2, 3, 4}
	b := []byte{5, 6, 7, 8}
	c := []byte{9, 10}
	e := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}

	d := vhead.GenerateHeadBuf(a, b, c)

	for i, v := range e {
		if d[i] == v {
			continue
		} else {
			flag = 1
		}
	}
	fmt.Println(flag)
	if flag == 1 {
		test.Error("Failed: TestGenerateHeadBuf")
	} else {

		test.Log("Passed: TestGenerateHeadBuf")
	}
}

//测试获取报文长度函数功能
func TestEncKeyLen(test *testing.T) {

	var vhead *Head
	a := IntToBytes(1200)

	d, _ := vhead.GetEncKeyLen(a)
	fmt.Println("d = ", d)

	if d == 1200 {
		test.Log("Passed: TestGetLicenseDataLen")
	} else {
		test.Error("Failed: TestGetLicenseDataLen")
	}
}

//==============================================================================
/*
 *测试文件格式加密对称秘钥对象的方法
 */
//==============================================================================
//测试对对称秘钥进行加解密的方法
func TestKeyEncrypt(test *testing.T) {
	var vEncKey *EncKey
	publicKey, err := ioutil.ReadFile("./examples/dec/public.pem")
	if err != nil {
		os.Exit(-1)
	}
	privateKey, err := ioutil.ReadFile("./examples/enc/private.pem")
	if err != nil {
		os.Exit(-1)
	}

	//RSA加密
	RsaEncKey, err := vEncKey.Encrypt(publicKey, []byte("1234567890abcdef"))
	if err != nil {
		panic(err)
	}

	//RSA解密
	origKeyData, err := vEncKey.Decrypt(privateKey, RsaEncKey)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(origKeyData))

	if string(origKeyData) == "1234567890abcdef" {
		test.Log("Passed: TestKeyEncrypt")
	} else {
		test.Error("Failed: TestKeyEncrypt")
	}
}

//==============================================================================
/*
 *以下为测试文件格式签名license原文对象的方法
 */
//==============================================================================
//测试对license原文进行签名验签的方法
func TestLicenseSign(test *testing.T) {
	var vSign *SignLicense
	publicKey, err := ioutil.ReadFile("./examples/dec/public.pem")
	if err != nil {
		os.Exit(-1)
	}
	privateKey, err := ioutil.ReadFile("./examples/enc/private.pem")
	if err != nil {
		os.Exit(-1)
	}
	Md5Buf := []byte("123456123456")

	//RSA签名
	signData, err := vSign.Sign(privateKey, Md5Buf, crypto.MD5)
	if err != nil {
		panic(err)
	}
	fmt.Println("signData type:", reflect.TypeOf(signData))
	fmt.Println(len(signData))
	//RSA验签
	err = vSign.Verify(publicKey, Md5Buf, signData, crypto.MD5)
	if err != nil {
		test.Error("Failed: TestLicenseSign")

	}
	test.Log("Passed: TestLicenseSign")
}

//==============================================================================
/*
 *以下为测试license报文对象的方法
 */
//==============================================================================

//测试压缩解压数据
func TestZipBytes(test *testing.T) {
	var vData *LicenseData
	var input = []byte("iVBORw0KGgoAAAANSUhEUgAAAKsAAAAgCAYAAABtn4gCAAAI9klEQVR4Xu2cfYxcVRmHn3Pu3Nm6lX")

	//压缩
	zipInput, _ := vData.ZipBytes(input)

	//解压
	UnZipOut, _ := vData.UnzipBytes(zipInput)

	if string(UnZipOut) == "iVBORw0KGgoAAAANSUhEUgAAAKsAAAAgCAYAAABtn4gCAAAI9klEQVR4Xu2cfYxcVRmHn3Pu3Nm6lX" {
		test.Log("Passed: TestZipBytes")
	} else {
		test.Error("Failed: TestZipBytes")
	}

}

//测试AES加解密
func TestEncrypt(test *testing.T) {
	var vData *LicenseData
	//AES加密
	aesKey := "1234567890123456"
	var input = []byte("iVBORw0KGgoAAAANSUhEUgAAAKsAAAAgCAYAAABtn4gCAAAI9klEQVR4Xu2cfYxcVRmHn3Pu3Nm6lX")
	AesEncText, err := vData.Encrypt(nil, []byte(aesKey), string(input[:]))
	if err != nil {
		panic(err)
	}
	fmt.Println(len(AesEncText))

	//AES解密
	strMsg, err := vData.Decrypt(nil, []byte(aesKey), AesEncText)
	if err != nil {
		panic(err)
	}

	if strMsg == "iVBORw0KGgoAAAANSUhEUgAAAKsAAAAgCAYAAABtn4gCAAAI9klEQVR4Xu2cfYxcVRmHn3Pu3Nm6lX" {
		test.Log("Passed: TestEncrypt")
	} else {
		test.Error("Failed: TestEncrypt")
	}
}
