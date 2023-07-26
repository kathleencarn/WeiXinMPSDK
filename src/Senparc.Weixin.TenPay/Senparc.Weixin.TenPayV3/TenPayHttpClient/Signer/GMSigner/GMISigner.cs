using System.Security.Cryptography;

namespace Client.TenPayHttpClient.Signer.GMSigner
{
	public interface GMISigner
	{
		/// <summary>
		/// 对数据进行签名
		/// </summary>
		/// <param name="data">要签名的数据</param>
		/// <param name="privateKey">用于签名的私钥</param>
		/// <returns>签名后的数据</returns>
		byte[] SignData(byte[] data, CngKey privateKey);

		/// <summary>
		/// 验证签名
		/// </summary>
		/// <param name="data">原始数据</param>
		/// <param name="signature">签名数据</param>
		/// <param name="publicKey">用于验证签名的公钥</param>
		/// <returns>验证结果，如果验证通过返回true，否则返回false</returns>
		bool VerifyData(byte[] data, byte[] signature, CngKey publicKey);
	}
}
