using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Collections.Generic;
using System.Text;

namespace SM2Crypto.Lib
{
    class SM2Utils
    {
        public enum Ctype { 
            C1C2C3,
            C1C3C2
        };

        /// <summary>
        /// 随机生成SM2密钥对
        /// </summary>
        /// <param name="pubk">公钥</param>
        /// <param name="prik">私钥</param>
        public static void GenerateKeyPair(out ECPoint pubk, out BigInteger prik)
        {
            SM2 sm2 = SM2.Instance;
            AsymmetricCipherKeyPair key = sm2.ecc_key_pair_generator.GenerateKeyPair();
            ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters)key.Private;
            ECPublicKeyParameters ecpub = (ECPublicKeyParameters)key.Public;
            BigInteger privateKey = ecpriv.D;
            ECPoint publicKey = ecpub.Q;
            pubk = publicKey;
            prik = privateKey;
        }

        /// <summary>
        /// 公钥加密
        /// </summary>
        /// <param name="publicKey">公钥</param>
        /// <param name="data">原始数据</param>
        /// <param name="C">C1\C2\C3排列方式</param>
        /// <returns>密文</returns>
        public static String Encrypt(byte[] publicKey, byte[] data, Ctype C)
        {
            if (null == publicKey || publicKey.Length == 0)
            {
                return null;
            }
            if (data == null || data.Length == 0)
            {
                return null;
            }

            byte[] source = new byte[data.Length];
            Array.Copy(data, 0, source, 0, data.Length);

            Cipher cipher = new Cipher();
            SM2 sm2 = SM2.Instance;

            ECPoint userKey = sm2.ecc_curve.DecodePoint(publicKey);

            ECPoint c1 = cipher.Init_enc(sm2, userKey);
            cipher.Encrypt(source);

            byte[] c3 = new byte[32];
            cipher.Dofinal(c3);

            String sc1 = Encoding.ASCII.GetString(Hex.Encode(c1.GetEncoded()));
            String sc2 = Encoding.ASCII.GetString(Hex.Encode(source));
            String sc3 = Encoding.ASCII.GetString(Hex.Encode(c3));
            if (C == Ctype.C1C2C3)
            {
                return sc1 + sc2 + sc3;
            }
            else {
                return sc1  + sc3 + sc2;
            }
        }

        /// <summary>
        /// 私钥解密
        /// </summary>
        /// <param name="privateKey">私钥</param>
        /// <param name="encryptedData">密文</param>
        /// <param name="C">C1\C2\C3排列方式</param>
        /// <returns>原始数据</returns>
        public static byte[] Decrypt(byte[] privateKey, byte[] encryptedData, Ctype C)
        {
            if (null == privateKey || privateKey.Length == 0)
            {
                return null;
            }
            if (encryptedData == null || encryptedData.Length == 0)
            {
                return null;
            }

            String data = Encoding.ASCII.GetString(Hex.Encode(encryptedData));

            byte[] c1Bytes = Hex.Decode(Encoding.ASCII.GetBytes(data.Substring(0, 130)));
            int c2Len = encryptedData.Length - 97;
            byte[] c3, c2;
            if (C == Ctype.C1C2C3)
            {
                c3 = Hex.Decode(Encoding.Default.GetBytes(data.Substring(130+ 2 * c2Len, 64)));
                c2 = Hex.Decode(Encoding.Default.GetBytes(data.Substring(130 , 2 * c2Len)));
            }
            else {
                c3 = Hex.Decode(Encoding.Default.GetBytes(data.Substring(130, 64)));
                c2 = Hex.Decode(Encoding.Default.GetBytes(data.Substring(130 + 64, 2 * c2Len)));
            }


            SM2 sm2 = SM2.Instance;
            BigInteger userD = new BigInteger(1, privateKey);

            ECPoint c1 = sm2.ecc_curve.DecodePoint(c1Bytes);
            Cipher cipher = new Cipher();
            cipher.Init_dec(userD, c1);
            cipher.Decrypt(c2);
            cipher.Dofinal(c3);

            return c2;
        }
    }
}
