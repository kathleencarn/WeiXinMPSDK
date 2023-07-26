using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using System;
using System.Security.Cryptography;

namespace Client.TenPayHttpClient.Signer.GMSigner
{
    public class SM3WithSM2GMSigner : GMISigner
    {
        public byte[] SignData(byte[] data, CngKey privateKey)
        {
            try
            {
                var signer = new SM2Signer();
                signer.Init(true, new ParametersWithRandom(PrivateKeyFactory.CreateKey(privateKey.Export(CngKeyBlobFormat.EccPrivateBlob)), new SecureRandom()));

                var hash = new SM3Digest();
                hash.BlockUpdate(data, 0, data.Length);
                var digest = new byte[hash.GetDigestSize()];
                hash.DoFinal(digest, 0);

                var signature = signer.GenerateSignature(digest);

                return signature;
            }
            catch (Exception ex)
            {
                // 处理异常
                return null;
            }
        }

        public bool VerifyData(byte[] data, byte[] signature, CngKey publicKey)
        {
            try
            {
                var signer = new SM2Signer();
                signer.Init(false, PublicKeyFactory.CreateKey(publicKey.Export(CngKeyBlobFormat.EccPublicBlob)));

                var hash = new SM3Digest();
                hash.BlockUpdate(data, 0, data.Length);
                var digest = new byte[hash.GetDigestSize()];
                hash.DoFinal(digest, 0);

                return signer.VerifySignature(digest, signature);
            }
            catch (Exception ex)
            {
                // 处理异常
                return false;
            }
        }
    }
}