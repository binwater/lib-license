package license

import (
	"bytes"
	"compress/zlib"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"bufio"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

//总license控制对象
type LicenseControl struct {
	sHead        Head        //license 文件格式 头对象
	sEncKey      EncKey      //license 文件格式 加密对称秘钥对象
	sSignLicense SignLicense //license 文件格式 签名license原文对象
	sLicenseData LicenseData //license 文件格式 license报文对象
	sSignData    SignData    //license 文件格式 全部内容签名对象
}

//license 文件格式头对象 36字节
type Head struct {
	EncKeyLen []byte //加密对称密钥长度 4
	SignLen   []byte //签名对象长度 4
	LicLen    []byte //license报文对象长度 4
	AllLicLen []byte //license 总长度 4
	KeyType   []byte //对称密钥信息 16
	OtherInfo []byte //预留其他信息 4
}

//license 文件格式加密对称秘钥对象
type EncKey struct {
	EncKeyBuf []byte
}

//license 文件格式签名license原文对象
type SignLicense struct {
	SignLicenseBuf []byte
}

//license 文件格式license报文对象
type LicenseData struct {
	LicenseDataBuf []byte
}

//license 文件格式全部内容签名对象
type SignData struct {
	SignDataBuf []byte
}

/**
 * @brief  整形转换成字节
 * @param[in]       n				  待转换整形数
 * @return   成功返回 int类型文件头的长度，失败返回error	错误信息
 */
func IntToBytes(n int) []byte {
	tmp := int32(n)
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.BigEndian, &tmp)
	return bytesBuffer.Bytes()
}

/**
 * @brief  字节转换成整形
 * @param[in]       b				   待转换字节数组
 * @return   无
 */
func BytesToInt(b []byte) int {
	bytesBuffer := bytes.NewBuffer(b)
	var tmp int32
	binary.Read(bytesBuffer, binary.BigEndian, &tmp)
	return int(tmp)
}

/**
 * @brief  获取RSA公钥长度
 * @param[in]       PubKey				    RSA公钥
 * @return   成功返回 RSA公钥长度，失败返回error	错误信息
 */
func GetPubKeyLen(PubKey []byte) (int, error) {
	if PubKey == nil {
		return 0, errors.New("input arguments error")
	}

	block, _ := pem.Decode(PubKey)
	if block == nil {
		return 0, errors.New("public rsaKey error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return 0, err
	}
	pub := pubInterface.(*rsa.PublicKey)

	fmt.Println("pbulic key len is ", pub.N.BitLen())
	return pub.N.BitLen(), nil
}

/**
 * @brief  获取RSA私钥长度
 * @param[in]       PriKey				    RSA私钥
 * @return   成功返回 RSA私钥长度，失败返回error	错误信息
 */
func GetPriKeyLen(PriKey []byte) (int, error) {
	if PriKey == nil {
		return 0, errors.New("input arguments error")
	}

	block, _ := pem.Decode(PriKey)
	if block == nil {
		return 0, errors.New("private rsaKey error!")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return 0, err
	}
	fmt.Println("private key len is ", priv.N.BitLen())

	return priv.N.BitLen(), nil
}

//==============================================================================
/*
 *以下方法为文件格式头对象的方法
 */
//==============================================================================
/**
 * @brief  生成文件头
 * @param[in]       []byte				    各个头信息byte数组
 * @return   成功返回 文件头byte数组，失败返回error	错误信息
 */
func (head *Head) GenerateHeadBuf(pBytes ...[]byte) []byte {
	return bytes.Join(pBytes, []byte(""))
}

/**
 * @brief  从文件头buf中获取加密密钥对象长度
 * @param[in]       HeadBuf				    文件头的数据内容
 * @return   成功返回 int类型加密密钥对象长度，失败返回error	错误信息
 */
func (head *Head) GetEncKeyLen(HeadBuf []byte) (int, error) {
	if HeadBuf == nil {
		return 0, errors.New("input arguments error")
	}

	EncKeyLenBuf := make([]byte, 4)
	copy(EncKeyLenBuf, HeadBuf[0:4])
	return BytesToInt(EncKeyLenBuf), nil
}

/**
 * @brief  从文件头buf中获取签名对象长度
 * @param[in]       HeadBuf				    文件头的数据内容
 * @return   成功返回 int类型签名对象长度，失败返回error	错误信息
 */
func (head *Head) GetSignLen(HeadBuf []byte) (int, error) {
	if HeadBuf == nil {
		return 0, errors.New("input arguments error")
	}

	SignLenBuf := make([]byte, 4)
	copy(SignLenBuf, HeadBuf[4:8])
	return BytesToInt(SignLenBuf), nil
}

/**
 * @brief  从文件头buf中获取license 报文对象长度
 * @param[in]       HeadBuf				    文件头的数据内容
 * @return   成功返回 int类型license 报文对象长度，失败返回error	错误信息
 */
func (head *Head) GetLicLen(HeadBuf []byte) (int, error) {
	if HeadBuf == nil {
		return 0, errors.New("input arguments error")
	}

	LicLenBuf := make([]byte, 4)
	copy(LicLenBuf, HeadBuf[8:12])
	return BytesToInt(LicLenBuf), nil
}

/**
 * @brief  从文件头buf中获取license总长度
 * @param[in]       HeadBuf				    文件头的数据内容
 * @return   成功返回 int类型license总长度，失败返回error	错误信息
 */
func (head *Head) GetAllLicLen(HeadBuf []byte) (int, error) {
	if HeadBuf == nil {
		return 0, errors.New("input arguments error")
	}

	AllLicLenBuf := make([]byte, 4)
	copy(AllLicLenBuf, HeadBuf[12:16])
	return BytesToInt(AllLicLenBuf), nil
}

/**
 * @brief  从文件头buf中获取对称秘钥信息
 * @param[in]       HeadBuf				    文件头的数据内容
 * @return   成功返回 对称秘钥信息，失败返回error	错误信息
 */
func (head *Head) GetKyeInfo(HeadBuf []byte) ([]byte, error) {
	if HeadBuf == nil {
		return nil, errors.New("input arguments error")
	}

	KyeInfo := make([]byte, 16)
	copy(KyeInfo, HeadBuf[16:32])
	return KyeInfo, nil
}

/**
 * @brief  从文件头buf中获取其他信息
 * @param[in]       HeadBuf				    文件头的数据内容
 * @return   成功返回 对称秘钥信息，失败返回error	错误信息
 */
func (head *Head) GetOtherInfo(HeadBuf []byte) ([]byte, error) {
	if HeadBuf == nil {
		return nil, errors.New("input arguments error")
	}

	OtherInfo := make([]byte, 4)
	copy(OtherInfo, HeadBuf[32:36])
	return OtherInfo, nil
}

//==============================================================================
/*
 *以下方法为文件格式加密对称秘钥对象的方法
 */
//==============================================================================
/**
 * @brief  对对称秘钥信息进行RSA加密
 * @param[in]       key				    RSA公钥
 * @param[in]       origData			待加密的明文
 * @return   成功返回 密文，失败返回error	错误信息
 */
func (key *EncKey) Encrypt(rsaKey []byte, origData []byte) ([]byte, error) {
	if rsaKey == nil || origData == nil {
		return nil, errors.New("input arguments error")
	}

	block, _ := pem.Decode(rsaKey)
	if block == nil {
		return nil, errors.New("public rsaKey error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub := pubInterface.(*rsa.PublicKey)
	return rsa.EncryptPKCS1v15(rand.Reader, pub, origData)
}

/**
 * @brief  对对称秘钥信息进行RSA解密
 * @param[in]       key				    RSA私钥
 * @param[in]       ciphertext			密文
 * @return   成功返回 密文，失败返回error	错误信息
 */
func (key *EncKey) Decrypt(rsaKey []byte, ciphertext []byte) ([]byte, error) {
	if rsaKey == nil || ciphertext == nil {
		return nil, errors.New("input arguments error")
	}

	block, _ := pem.Decode(rsaKey)
	if block == nil {
		return nil, errors.New("private rsaKey error!")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
}

//==============================================================================
/*
 *以下方法为文件格式签名license原文对象的方法
 */
//==============================================================================
/**
 * @brief  对报文做MD5运算
 * @param[in]       plantext			待做MD5运算的原始数据
 * @return   成功返回 密文，失败返回error	错误信息
 */
func (license *SignLicense) Md5Encrypt(plantext []byte) ([]byte, error) {
	if plantext == nil {
		return nil, errors.New("input arguments error")
	}

	result := md5.Sum(plantext)
	return result[:], nil
}

/**
 * @brief  Rsa签名
 * @param[in]       key				    RSA私钥
 * @param[in]       src					待签名数据
 * @param[in]       hash				使用的hash算法
 * @return   成功返回 密文，失败返回error	错误信息
 */
func (sign *SignLicense) Sign(key []byte, src []byte, hash crypto.Hash) ([]byte, error) {
	if key == nil || src == nil {
		return nil, errors.New("input arguments error")
	}

	block, _ := pem.Decode(key)
	if block == nil {
		return nil, errors.New("private key error!")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	h := hash.New()
	h.Write(src)
	hashed := h.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, priv, hash, hashed)
}

/**
 * @brief  Rsa验签
 * @param[in]       key				    RSA公钥
 * @param[in]       src					原始数据
 * @param[in]       sign				签名数据
 * @param[in]       hash				使用的hash算法
 * @return   成功返回 ，失败返回error	错误信息
 */
func (sign *SignLicense) Verify(key []byte, src []byte, rsaSign []byte, hash crypto.Hash) error {
	if key == nil || src == nil || rsaSign == nil {
		return errors.New("input arguments error")
	}

	block, _ := pem.Decode(key)
	if block == nil {
		return errors.New("public key error!")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	pub := pubInterface.(*rsa.PublicKey)

	h := hash.New()
	h.Write(src)
	hashed := h.Sum(nil)
	return rsa.VerifyPKCS1v15(pub, hash, hashed, rsaSign)
}

//==============================================================================
/*
 *以下方法为license报文对象的方法
 */
//==============================================================================
/**
 * @brief  读取原报文文件内容
 * @param[in]       name			文件名（可以加路径）
 * @return   成功返回 文件内容，失败返回error	错误信息
 */
func (license *LicenseData) ReadFile(name string) ([]byte, error) {
	if len(name) == 0 {
		return nil, errors.New("input arguments error")
	}

	//打开本地文件 读取出全部数据
	fin, err := os.Open(name)
	defer fin.Close()
	if err != nil {
		return nil, errors.New("Close file error")
	}

	buf_len, _ := fin.Seek(0, os.SEEK_END)
	fin.Seek(0, os.SEEK_SET)

	buf := make([]byte, buf_len)
	fin.Read(buf)

	return buf, nil
}

/**
 * @brief  压缩数据到内存中
 * @param[in]       input			待压缩数据
 * @return   成功返回 压缩后数据，失败返回error	错误信息
 */
func (license *LicenseData) ZipBytes(input []byte) ([]byte, error) {
	if input == nil {
		return nil, errors.New("input arguments error")
	}

	var buf bytes.Buffer
	compressor, err := zlib.NewWriterLevel(&buf, zlib.BestSpeed)
	if err != nil {
		return input, errors.New("zlib error")
	}
	compressor.Write(input)
	compressor.Close()
	return buf.Bytes(), nil
}

/**
 * @brief  加密数据
 * @param[in]       key				AES秘钥
 * @param[in]       strMesg			待加密数据
 * @return   成功返回 密文，失败返回error	错误信息
 */
func (license *LicenseData) Encrypt(encType []byte, key []byte, strMesg string) ([]byte, error) {
	if key == nil || len(strMesg) == 0 {
		return nil, errors.New("input arguments error")
	}

	var iv = []byte(key)[:aes.BlockSize]
	encrypted := make([]byte, len(strMesg))
	aesBlockEncrypter, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesEncrypter := cipher.NewCFBEncrypter(aesBlockEncrypter, iv)
	aesEncrypter.XORKeyStream(encrypted, []byte(strMesg))
	return encrypted, nil
}

/**
 * @brief  解密数据
 * @param[in]       key			AES秘钥
 * @param[in]       src			加密数据
 * @return   成功返回 解密后数据，失败返回error	错误信息
 */
func (license *LicenseData) Decrypt(encType []byte, key []byte, src []byte) (strDesc string, err error) {
	if key == nil || src == nil {
		return "", errors.New("input arguments error")
	}

	defer func() {
		//错误处理
		if e := recover(); e != nil {
			err = e.(error)
		}
	}()

	var iv = []byte(key)[:aes.BlockSize]
	decrypted := make([]byte, len(src))
	var aesBlockDecrypter cipher.Block
	aesBlockDecrypter, err = aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	aesDecrypter := cipher.NewCFBDecrypter(aesBlockDecrypter, iv)
	aesDecrypter.XORKeyStream(decrypted, src)
	return string(decrypted), nil
}

/**
 * @brief  解压数据到内存中
 * @param[in]       input			待压缩数据
 * @return   成功返回 解压后数据，失败返回error	错误信息
 */
func (license *LicenseData) UnzipBytes(input []byte) ([]byte, error) {
	if input == nil {
		return nil, errors.New("input arguments error")
	}

	b := bytes.NewReader(input)
	r, err := zlib.NewReader(b)
	defer r.Close()
	if err != nil {
		return nil, err
	}
	data, _ := ioutil.ReadAll(r)
	return data, nil
}

//==============================================================================
/*
 *以下方法为SignData对象的方法
 */
//==============================================================================
/**
 * @brief  对整体报文做MD5运算
 * @param[in]       plantext			待做MD5运算的原始数据
 * @return   成功返回 密文，失败返回error	错误信息
 */
func (sign *SignData) Md5Encrypt(plantext []byte) ([]byte, error) {
	if plantext == nil {
		return nil, errors.New("input arguments error")
	}

	result := md5.Sum(plantext)
	return result[:], nil
}

/**
 * @brief  生成前四个对象合并数据
 * @param[in]       []byte				    各个对象byte数组
 * @return   成功返回 前四个对象合并数据，失败返回error	错误信息
 */
func (sign *SignData) GenerateEncBuf(pBytes ...[]byte) []byte {
	return bytes.Join(pBytes, []byte(""))
}

//==============================================================================
/*
 *以下方法为总license控制对象的方法
 */
//==============================================================================
/**
 * @brief  生成密文格式数据
 * @param[in]       []byte				    各个对象byte数组
 * @return   成功返回 密文格式数据byte数组，失败返回error	错误信息
 */
func (license *LicenseControl) GenerateEncBuf(pBytes ...[]byte) []byte {
	return bytes.Join(pBytes, []byte(""))
}

/**
 * @brief  对原始数据进行base64编码
 * @param[in]       []byte				    各个对象byte数组
 * @return   成功返回 密文格式数据byte数组，失败返回error	错误信息
 */
func (license *LicenseControl) Base64Enc(input []byte) (string, error) {
	if input == nil {
		return "", errors.New("input arguments error")
	}

	// base64编码
	encodeString := base64.StdEncoding.EncodeToString(input)
	return encodeString, nil
}

/**
 * @brief			写入数据到指定名字的文件中
 * @param[in]       buf				    待写入的数据内容
 * @param[in]       name				文件名字
 * @return   成功返回 失败返回error	错误信息
 */
func (license *LicenseControl) WriteFile(buf string, name string) error {
	if len(buf) == 0 || len(name) == 0 {
		return errors.New("input arguments error")
	}

	fout, err := os.Create(name)
	defer fout.Close()
	if err != nil {
		return err
	}

	//写入到本地文件中
	fout.WriteString(buf)

	return nil
}

/**
 * @brief  读取原报文文件内容
 * @param[in]       name			文件名（可以加路径）
 * @return   成功返回 文件内容，失败返回error	错误信息
 */
func (license *LicenseControl) ReadFile(name string) ([]byte, error) {
	if len(name) == 0 {
		return nil, errors.New("input arguments error")
	}

	//打开本地文件 读取出全部数据
	fin, err := os.Open(name)
	defer fin.Close()
	if err != nil {
		return nil, errors.New("Close error")
	}

	buf_len, _ := fin.Seek(0, os.SEEK_END)
	fin.Seek(0, os.SEEK_SET)

	buf := make([]byte, buf_len)
	fin.Read(buf)

	return buf, nil
}

/**
 * @brief  对base64数据进行解码
 * @param[in]       []byte				    各个对象byte数组
 * @return   成功返回 密文格式数据byte数组，失败返回error	错误信息
 */
func (license *LicenseControl) Base64Dec(encodeString string) ([]byte, error) {
	if len(encodeString) == 0 {
		return nil, errors.New("input arguments error")
	}

	// base64解码
	decodeBytes, err := base64.StdEncoding.DecodeString(encodeString)
	if err != nil {
		return nil, errors.New("DecodeString error")
	}

	return decodeBytes, nil
}

/**
 * @brief  对明文进行加密 服务端操作
 * @param[in]        clientInfo				  客户端信息
 * @param[in]        license				  license内容
 * @param[in]        privateKey			  	  自身私钥
 * @param[out]       cipherText				  输出密文字符串
 * @return   成功返回 cipherText，nil，失败返回error	错误信息
 */
func EncLicenseSer(clientInfo string, license string, privateKey []byte) (string, error) {
	if len(clientInfo) == 0 || len(license) == 0 || privateKey == nil {
		return "", errors.New("input arguments error")
	}
	const macUuidLen int = 42
	var pubKeyLen int
	vGateInfo := []byte(clientInfo)
	pubKeyLen = len(vGateInfo) - macUuidLen

	//vgate 公钥
	var v_publicKey = make([]byte, pubKeyLen)
	copy(v_publicKey, vGateInfo[0:pubKeyLen])

	var mac_uuid = make([]byte, macUuidLen)
	copy(mac_uuid, vGateInfo[pubKeyLen:len(vGateInfo)])

	var head Head //声明一个文件格式头对象的指针
	//对 license报文对象进行加密流程处理
	var initLic *LicenseData //声明一个LicenseData对象的指针
	//读取明文
	PlainText := []byte(license)

	//对明文进行压缩
	ZipText, err := initLic.ZipBytes(PlainText)
	if err != nil {
		return "", err
	}

	//AES加密压缩文件
	aesKey := "1234567890123456"
	AesEncLicense, err := initLic.Encrypt(nil, []byte(aesKey), string(ZipText[:]))
	if err != nil {
		return "", err
	}
	LicInfoLen := len(AesEncLicense) + macUuidLen
	head.LicLen = IntToBytes(LicInfoLen) //记录lic长度

	//对 签名license原文对象进行处理
	var vSign *SignLicense //声明一个签名license原文对象的指针
	//MD5对明文运算
	Md5BufLicense, err := vSign.Md5Encrypt(PlainText)
	if err != nil {
		return "", err
	}

	//RSA签名
	signData, err := vSign.Sign(privateKey, Md5BufLicense, crypto.MD5)
	if err != nil {
		return "", err
	}
	head.SignLen = IntToBytes(len(signData)) //记录签名长度

	//对 加密对称秘钥对象进行处理
	var vEncKey *EncKey //声明一个加密对称秘钥对象的指针
	//RSA加密
	RsaEncKey, err := vEncKey.Encrypt(v_publicKey, []byte(aesKey))
	if err != nil {
		return "", err
	}
	head.EncKeyLen = IntToBytes(len(RsaEncKey)) //记录加密对称密钥长度

	//对 文件格式头对象进行处理
	const headLen int = 36
	const AllDataMd5Len int = 16

	//生成license总长度的 4 byte
	var AllLen int = headLen + len(RsaEncKey) + len(signData) + LicInfoLen + AllDataMd5Len
	head.AllLicLen = IntToBytes(AllLen) //记录总长度

	//生成对称秘钥信息 16 byte
	head.KeyType = make([]byte, 16)

	//生成其他信息 4 byte
	head.OtherInfo = make([]byte, 4) //记录公钥长度

	//合并为头head信息
	HeadBuf := head.GenerateHeadBuf(head.EncKeyLen, head.SignLen, head.LicLen,
		head.AllLicLen, head.KeyType, head.OtherInfo)

	//对 全部内容对象进行签名处理
	var sign *SignData //声明一个全部内容签名对象的指针
	//生成前四个对象合并数据
	EncBuf := sign.GenerateEncBuf(HeadBuf, RsaEncKey, signData, mac_uuid, AesEncLicense)

	//进行md5加密
	Md5All, err := sign.Md5Encrypt(EncBuf)
	if err != nil {
		return "", err
	}

	//对 总license控制对象进行处理
	var data *LicenseControl //声明一个总license控制对象的指针
	//生成前四个对象合并数据
	EncAll := data.GenerateEncBuf(EncBuf, Md5All)

	//进行base64编码
	baseEncAll, err := data.Base64Enc(EncAll)
	if err != nil {
		return "", err
	}

	fmt.Println("output enc license successful")

	return string(baseEncAll), nil

}

/**
 * @brief  对密文进行解析为明文 服务端操作（密文为客户端公钥+其他信息组成）
 * @param[in]         cipherText			  输入密文字符串
 * @param[in]         privateKey			  输入私钥
 * @param[out]        plainText				  输出明文字符串
 * @return   成功返回 nil，失败返回error	  错误信息
 */
func DecLicenseSer(cipherText string, privateKey []byte) (string, error) {
	if len(cipherText) == 0 || privateKey == nil {
		return "", errors.New("input arguments error")
	}

	//对 总license控制对象进行处理
	var data *LicenseControl

	//对上面的编码结果进行base64解码
	decodeBytes, err := data.Base64Dec(string(cipherText))
	if err != nil {
		return "", err
	}

	//对 文件格式头对象进行处理
	var head *Head //声明一个文件格式头对象的指针
	const HeadLen int = 36
	headBuf := make([]byte, HeadLen)
	copy(headBuf, decodeBytes[:HeadLen])
	//获取报文总长度的 4 byte
	AllLen, err := head.GetAllLicLen(headBuf)
	if err != nil {
		return "", err
	}

	//声明一个签名license原文对象的指针
	var vSign *SignLicense
	const md5Len int = 16

	AllData := make([]byte, AllLen-md5Len)
	copy(AllData, decodeBytes[0:(AllLen-md5Len)])

	licMd5 := make([]byte, md5Len)
	copy(licMd5, decodeBytes[(AllLen-md5Len):AllLen])

	//对所有数据的md5进行验证
	AllMd5Buf, err := vSign.Md5Encrypt(AllData)
	if err != nil {
		return "", err
	}

	var j int
	for j = 0; j < md5Len; j++ {
		if AllMd5Buf[j] == licMd5[j] {
			continue
		} else {
			return "", errors.New("enc file is invalid.")

		}
	}

	//对 加密对称秘钥对象进行处理
	var vEncKey *EncKey
	EncKeyLen, _ := head.GetEncKeyLen(decodeBytes[:HeadLen])

	//RSA解密对称秘钥
	EncAesKey := make([]byte, EncKeyLen)
	copy(EncAesKey, decodeBytes[HeadLen:HeadLen+EncKeyLen])
	origKeyData, err := vEncKey.Decrypt(privateKey, EncAesKey)
	if err != nil {
		return "", err
	}

	//对 license报文对象进行加密流程处理
	var initLic *LicenseData
	SignLen, _ := head.GetSignLen(decodeBytes[:HeadLen])
	BeforeLicLen := HeadLen + EncKeyLen + SignLen

	//AES解密压缩文件
	EncLicenseLen, err := head.GetLicLen(headBuf)
	AesEncText := make([]byte, EncLicenseLen)
	copy(AesEncText, decodeBytes[BeforeLicLen:BeforeLicLen+EncLicenseLen])
	strMsg, err := initLic.Decrypt(nil, origKeyData, []byte(AesEncText))
	if err != nil {
		return "", err
	}

	//解压压缩文件
	TarGzText, err := initLic.UnzipBytes([]byte(strMsg))
	if err != nil {
		return "", err
	}

	//获取 客户端 公钥
	PubKeyLenBuf, _ := head.GetOtherInfo(headBuf)
	PubKeyLen := BytesToInt(PubKeyLenBuf)
	var c_publicKey = make([]byte, PubKeyLen)
	copy(c_publicKey, TarGzText[0:PubKeyLen])

	signInfo := make([]byte, SignLen)
	copy(signInfo, decodeBytes[HeadLen+EncKeyLen:BeforeLicLen])
	//MD5对明文运算
	Md5Buf, err := vSign.Md5Encrypt(TarGzText)
	if err != nil {
		return "", err
	}

	//RSA验签
	err = vSign.Verify(c_publicKey, Md5Buf, signInfo, crypto.MD5)
	if err != nil {
		return "", err
	}

	return string(TarGzText), nil
}

type UUID [16]byte

var hardwareAddr []byte

func TimeUUID() UUID {
	return FromTime(time.Now())
}

func FromTime(aTime time.Time) UUID {
	var u UUID
	var timeBase = time.Date(1582, time.October, 15, 0, 0, 0, 0, time.UTC).Unix()
	var clockSeq uint32
	utcTime := aTime.In(time.UTC)

	t := uint64(utcTime.Unix()-timeBase)*10000000 + uint64(utcTime.Nanosecond()/100)
	u[0], u[1], u[2], u[3] = byte(t>>24), byte(t>>16), byte(t>>8), byte(t)
	u[4], u[5] = byte(t>>40), byte(t>>32)
	u[6], u[7] = byte(t>>56)&0x0F, byte(t>>48)

	clock := atomic.AddUint32(&clockSeq, 1)
	u[8] = byte(clock >> 8)
	u[9] = byte(clock)

	copy(u[10:], hardwareAddr)

	u[6] |= 0x10 // set version to 1 (time based uuid)
	u[8] &= 0x3F // clear variant
	u[8] |= 0x80 // set to IETF variant

	return u
}

func (u UUID) String() string {
	var offsets = [...]int{0, 2, 4, 6, 9, 11, 14, 16, 19, 21, 24, 26, 28, 30, 32, 34}
	const hexString = "0123456789abcdef"
	r := make([]byte, 36)
	for i, b := range u {
		r[offsets[i]] = hexString[b>>4]
		r[offsets[i]+1] = hexString[b&0xF]
	}
	r[8] = '-'
	r[13] = '-'
	r[18] = '-'
	r[23] = '-'
	return string(r)
}

//合并byte[]
func MergeVgateInfo(pBytes ...[]byte) []byte {
	return bytes.Join(pBytes, []byte(""))
}

//产生vgate端RSA公私密钥
func GenRsaKey(bits int) error {
	// 生成私钥文件
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}
	derStream := x509.MarshalPKCS1PrivateKey(privateKey)
	block := &pem.Block{
		Type:  "私钥",
		Bytes: derStream,
	}
	file, err := os.Create("/produce/vgate_private.pem")
	if err != nil {
		return err
	}
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}

	// 生成公钥文件
	publicKey := &privateKey.PublicKey
	derPkix, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}
	block = &pem.Block{
		Type:  "公钥",
		Bytes: derPkix,
	}
	file, err = os.Create("/produce/vgate_public.pem")
	if err != nil {
		return err
	}
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}
	return nil
}

//go读取配置文件
func InitConfig(path string) map[string]string {
	//初始化
	myMap := make(map[string]string)

	//打开文件指定目录，返回一个文件f和错误信息
	f, err := os.Open(path)

	//异常处理 以及确保函数结尾关闭文件流
	if err != nil {
		panic(err)
	}
	defer f.Close()

	//创建一个输出流向该文件的缓冲流*Reader
	r := bufio.NewReader(f)
	for {
		//读取，返回[]byte 单行切片给b
		b, _, err := r.ReadLine()
		if err != nil {
			if err == io.EOF {
				break
			}
			panic(err)
		}

		//去除单行属性两端的空格
		s := strings.TrimSpace(string(b))

		//判断等号=在该行的位置
		index := strings.Index(s, "=")
		if index < 0 {
			continue
		}
		//取得等号左边的key值，判断是否为空
		key := strings.TrimSpace(s[:index])
		if len(key) == 0 {
			continue
		}

		//取得等号右边的value值，判断是否为空
		value := strings.TrimSpace(s[index+1:])
		if len(value) == 0 {
			continue
		}
		//这样就成功吧配置文件里的属性key=value对，成功载入到内存中c对象里
		myMap[key] = value
	}
	return myMap
}

/**
 * @brief  对客户端采集信息进行加密 客户端操作
 * @param[in]         KeyLen			  客户端公私密钥长度
 * @param[in]         publicKey			  服务端公钥
 * @param[out]        enc_client_info		  输出加密的客户端信息
 * @return   成功返回 nil，失败返回error	  错误信息
 */
func GenerateInfoCli(KeyLen string, publicKey []byte) (string, error) {
	if len(KeyLen) == 0 || publicKey == nil {
		return "", errors.New("error: input arguments error")
	}

	var bits int
	bits, _ = strconv.Atoi(KeyLen)
	//产生公私密钥
	if err := GenRsaKey(bits); err != nil {
		return "", err
	}

	//定义RSA局部公私密钥
	var v_privateKey []byte

	v_privateKey, err := ioutil.ReadFile("/produce/vgate_private.pem")
	if err != nil {
		return "", err
	}

	//获取mac地址信息
	var mac = make([]byte, 6)
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, inter := range interfaces {
		if len(inter.HardwareAddr) == 0 {
			continue
		}
		mac = inter.HardwareAddr
	}
	hardwareAddr = mac

	//生成uuid方法
	outUuid := TimeUUID()

	//加载vGate公钥信息
	//打开本地文件 读取出全部数据
	fin, err := os.Open("/produce/vgate_public.pem")
	defer fin.Close()
	if err != nil {
		return "", err
	}

	keyBuf := make([]byte, bits)
	fin.Read(keyBuf)

	//拼接vgate端信息 分别为公钥长度(1024\2048) 6 36 公钥 mac uuid
	uuidBuf := outUuid.String()
	infoBuf := MergeVgateInfo(keyBuf, mac, ([]byte)(uuidBuf))

	var data *LicenseControl //声明一个总license控制对象的指针
	// 写入指定文件
	err = data.WriteFile(string(uuidBuf), "/produce/vgateInfo")
	if err != nil {
		return "", err
	}

	var head Head //声明一个文件格式头对象的指针

	//对 license报文对象进行加密流程处理
	var initLic *LicenseData //声明一个LicenseData对象的指针

	//对明文进行压缩
	ZipText, err := initLic.ZipBytes(infoBuf)
	if err != nil {
		return "", err
	}

	//AES加密压缩文件
	aesKey := "1234567890123456"
	AesEncText, err := initLic.Encrypt(nil, []byte(aesKey), string(ZipText[:]))
	if err != nil {
		return "", err
	}
	head.LicLen = IntToBytes(len(AesEncText)) //记录lic长度

	//对 签名license原文对象进行处理
	var vSign *SignLicense //声明一个签名license原文对象的指针

	//MD5对明文运算
	Md5Buf, err := vSign.Md5Encrypt(infoBuf)
	if err != nil {
		return "", err
	}

	//RSA签名
	signData, err := vSign.Sign(v_privateKey, Md5Buf, crypto.MD5)
	if err != nil {
		return "", err
	}
	head.SignLen = IntToBytes(len(signData)) //记录签名长度

	//对 加密对称秘钥对象进行处理
	var vEncKey *EncKey //声明一个加密对称秘钥对象的指针

	//RSA加密
	RsaEncKey, err := vEncKey.Encrypt(publicKey, []byte(aesKey))
	if err != nil {
		return "", err
	}
	head.EncKeyLen = IntToBytes(len(RsaEncKey)) //记录加密对称密钥长度

	// 对 文件格式头对象进行处理
	const headLen int = 36
	const AllDataMd5Len int = 16

	//生成license总长度的 4 byte
	var AllLen int = headLen + len(RsaEncKey) + len(signData) + len(AesEncText) + AllDataMd5Len
	head.AllLicLen = IntToBytes(AllLen) //记录总长度

	//生成对称秘钥信息 16 byte
	head.KeyType = make([]byte, 16)

	//生成其他信息 4 byte
	head.OtherInfo = IntToBytes(bits) //记录公钥长度

	//合并为头head信息
	HeadBuf := head.GenerateHeadBuf(head.EncKeyLen, head.SignLen, head.LicLen,
		head.AllLicLen, head.KeyType, head.OtherInfo)

	//对 全部内容对象进行签名处理
	var sign *SignData //声明一个全部内容签名对象的指针

	//生成前四个对象合并数据
	EncBuf := sign.GenerateEncBuf(HeadBuf, RsaEncKey, signData, AesEncText)

	//进行md5加密
	Md5All, err := sign.Md5Encrypt(EncBuf)
	if err != nil {
		return "", err
	}

	//对 总license控制对象进行处理
	//生成前四个对象合并数据
	EncAll := data.GenerateEncBuf(EncBuf, Md5All)

	//进行base64编码
	baseEncAll, err := data.Base64Enc(EncAll)
	if err != nil {
		return "", err
	}
	return baseEncAll, nil
}

/**
 * @brief  对license 密文进行解密 客户端操作
 * @param[in]         enc_license	          服务端发送过来的license密文
 * @param[out]        dec_license		  解析出的license明文
 * @return   成功返回 nil，失败返回error	  错误信息
 */
func DecLicenseCli(enc_license string) (string, error) {
	if len(enc_license) == 0 {
		return "", errors.New("error: input arguments error")
	}

	//定义RSA局部公私密钥
	var v_privateKey []byte
	var publicKey []byte

	v_privateKey, err := ioutil.ReadFile("/produce/vgate_private.pem")
	if err != nil {
		return "", errors.New("3")
	}

	//服务端 公钥
	publicKey, err = ioutil.ReadFile("/tos/etc/public.pem")
	if err != nil {
		return "", errors.New("3")
	}

	//对 总license控制对象进行处理
	var data *LicenseControl //声明一个总license控制对象的指针

	//对上面的编码结果进行base64解码
	decodeBytes, err := data.Base64Dec(enc_license)
	if err != nil {
		return "", errors.New("4")
	}

	//对 文件格式头对象进行处理
	var head *Head //声明一个文件格式头对象的指针
	const HeadLen int = 36
	headBuf := make([]byte, HeadLen)
	copy(headBuf, decodeBytes[:HeadLen])
	//获取报文总长度的 4 byte
	AllLen, err := head.GetAllLicLen(headBuf)
	if err != nil {
		return "", err
	}

	//声明一个签名license原文对象的指针
	var vSign *SignLicense
	const md5Len int = 16

	AllData := make([]byte, AllLen-md5Len)
	copy(AllData, decodeBytes[0:(AllLen-md5Len)])

	licMd5 := make([]byte, md5Len)
	copy(licMd5, decodeBytes[(AllLen-md5Len):AllLen])

	//对所有数据的md5进行验证
	AllMd5Buf, err := vSign.Md5Encrypt(AllData)
	if err != nil {
		return "", err
	}

	var j int
	for j = 0; j < md5Len; j++ {
		if AllMd5Buf[j] == licMd5[j] {
			continue
		} else {
			return "", errors.New("5")

		}
	}

	//对比mac和uuid 与本地是否一致
	//读取本地存放信息
	localUuidInfo, err := data.ReadFile("/produce/vgateInfo")
	if err != nil {
		return "", errors.New("3")
	}

	//获取mac地址信息
	var mac = make([]byte, 6)
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, inter := range interfaces {
		if len(inter.HardwareAddr) == 0 {
			continue
		}
		mac = inter.HardwareAddr
	}
	localInfo := MergeVgateInfo(mac, localUuidInfo)

	//获取server端发送过来的设备信息
	const macUuidLen int = 42
	EncKeyLen, _ := head.GetEncKeyLen(headBuf) //加密密钥长度
	SignLen, _ := head.GetSignLen(headBuf)     //签名对象长度
	BeforeLicLen := HeadLen + EncKeyLen + SignLen

	remoteInfo := make([]byte, macUuidLen)
	copy(remoteInfo, decodeBytes[BeforeLicLen:(BeforeLicLen+macUuidLen)])

	//判断本地信息和远程信息是否相同
	var flag int
	for i, v := range localInfo {
		if remoteInfo[i] == v {
			continue
		} else {
			flag = 1
			break
		}
	}

	if flag == 1 {
		return "", errors.New("1")
	}

	//对 加密对称秘钥对象进行处理
	var vEncKey *EncKey //声明一个加密对称秘钥对象的指针

	//RSA解密对称秘钥
	EncAesKey := make([]byte, EncKeyLen)
	copy(EncAesKey, decodeBytes[HeadLen:HeadLen+EncKeyLen])
	origKeyData, err := vEncKey.Decrypt(v_privateKey, EncAesKey)
	if err != nil {
		return "", err
	}

	//对 license报文对象进行加密流程处理
	var initLic *LicenseData //声明一个LicenseData对象的指针

	//AES解密压缩文件
	//获取加密后报文长度的 4 byte
	EncLicInfoLen, err := head.GetLicLen(headBuf)
	EncLicenseLen := EncLicInfoLen - macUuidLen

	AesEncText := make([]byte, EncLicenseLen)
	copy(AesEncText, decodeBytes[(BeforeLicLen+macUuidLen):(BeforeLicLen+EncLicInfoLen)])
	strMsg, err := initLic.Decrypt(nil, origKeyData, []byte(AesEncText))
	if err != nil {
		return "", err
	}

	//解压压缩文件
	UnZipText, err := initLic.UnzipBytes([]byte(strMsg))
	if err != nil {
		return "", err
	}

	//对 license明文进行md5操作和验证签名
	signInfo := make([]byte, SignLen)
	copy(signInfo, decodeBytes[HeadLen+EncKeyLen:BeforeLicLen])
	//MD5对明文运算
	Md5Buf, err := vSign.Md5Encrypt(UnZipText)
	if err != nil {
		return "", err
	}

	//RSA验签
	err = vSign.Verify(publicKey, Md5Buf, signInfo, crypto.MD5)
	if err != nil {
		return "", err
	}

	//获取license中的到期时间
	configMap := InitConfig("/produce/option")
	//获取配置里VGATE_EXPIRE属性的value
	licenseTime := configMap["VGATE_EXPIRE"]

	//对比license中时间与本地时间
	localTime := time.Now().Format("2006-01-02")

	//先把时间字符串格式化成相同的时间类型
	t1, err := time.Parse("2006-01-02", localTime)
	t2, err := time.Parse("2006-01-02", string(licenseTime))
	if err == nil && t1.Before(t2) {
	} else {
		return "", errors.New("2")
	}

	return string(UnZipText), err
}
