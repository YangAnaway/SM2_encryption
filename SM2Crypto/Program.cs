using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities.Encoders;
using SM2Crypto.Lib;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SM2Crypto
{
    class Program
    {
        //TestSm2GetKeyPair()方法生成公钥、私钥
        private static  string PubKey= "041F59C1992CE0C09A0728ACD7E605F71C42064EA336D6EB166473903C61D332ED015C32CDA4A9C4A9486B34FB2025D8D7CECA664BF7896B13E31BF9976BC2DBE0";
        private static  string PriKey = "00E367370D017D5EDFE90A22D21C70CC720BBACF7F1DB8368DA151EDDA31B2F7D2";

        // 报送文件加密用公钥1 测试阶段无需修改，生产接入时另行发放
        public static readonly string PUB_X_KEY = "";
	    // 报送文件加密用公钥2 测试阶段无需修改，生产接入时另行发放
	    public static readonly string PUB_Y_KEY = "";
	    // 反馈文件解密用私钥 测试阶段无需修改，生产接入时另行发放
	    public static readonly string PRV_KEY = "";

        static void Main(string[] args)
        {

            ////生成公钥私钥对
            //  TestSm2GetKeyPair();

            ////测试公私钥字符串加解密
            TestSm2Enc();

            ///用于SM2私钥文件解密
           // tesdDecFile();

            Console.WriteLine("finish work");
            Console.ReadKey();
        }

        /// <summary>
        /// 生成公钥私钥对
        /// </summary>
        public static void TestSm2GetKeyPair()
        {
            SM2Utils sm2Utils = new SM2Utils();
            ECPoint pubk;
            BigInteger prik;
            SM2Utils.GenerateKeyPair( out pubk,  out prik);
            PubKey = Encoding.ASCII.GetString(Hex.Encode(pubk.GetEncoded())).ToUpper();
            PriKey = Encoding.ASCII.GetString(Hex.Encode(prik.ToByteArray())).ToUpper();
            System.Console.Out.WriteLine("公钥: " + Encoding.ASCII.GetString(Hex.Encode(pubk.GetEncoded())).ToUpper());
            System.Console.Out.WriteLine("私钥: " + Encoding.ASCII.GetString(Hex.Encode(prik.ToByteArray())).ToUpper());
        }

        /// <summary>
        /// 测试公私钥字符串加解密
        /// </summary>
        public static  void TestSm2Enc()
        {
            //SM2Utils.ccain();
            string testStr = "4C2B7D1C";
            Console.WriteLine("原始数据 : " + testStr);

            byte[] sourceData = Encoding.Default.GetBytes(testStr);
            string encStr =  SM2Utils.Encrypt(Hex.Decode(PubKey), sourceData,SM2Utils.Ctype.C1C2C3);
            Console.WriteLine("加密后数据 : " + encStr);
          
            String plainText = Encoding.Default.GetString(SM2Utils.Decrypt(Hex.Decode(PriKey), Hex.Decode(encStr), SM2Utils.Ctype.C1C2C3));
            Console.WriteLine("解密后数据 : " + plainText);
        }

        /// <summary>
        /// 用于SM2私钥文件解密
        /// </summary>
        public static void tesdDecFile()
        {
            string filePath = @"D:\ProjectDemo\SM2Crypto\tmp\MA05M6KK9201810311620120201.enc";
            FileStream fs = new FileStream(filePath, FileMode.Open);
            byte[] data = new byte[fs.Length];
            fs.Seek(0, SeekOrigin.Begin);
            fs.Read(data, 0, (int)fs.Length);
            fs.Close();

            byte[] prik = Encoding.ASCII.GetBytes(PRV_KEY);
            var decodedData = SM2Utils.Decrypt(Hex.Decode(prik), data, SM2Utils.Ctype.C1C3C2);

            string zipFilePath = @"D:\ProjectDemo\SM2Crypto\test\MA05M6KK9201810311620120201.zip";
            FileStream zfs = new FileStream(zipFilePath, FileMode.Create);
            zfs.Write(decodedData, 0, decodedData.Length);
            zfs.Close();
        }
    }
}
