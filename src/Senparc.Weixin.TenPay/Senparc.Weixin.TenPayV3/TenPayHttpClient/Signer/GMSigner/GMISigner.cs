using System.Security.Cryptography;

namespace Client.TenPayHttpClient.Signer.GMSigner
{
	public interface GMISigner
	{
		/// <summary>
		/// �����ݽ���ǩ��
		/// </summary>
		/// <param name="data">Ҫǩ��������</param>
		/// <param name="privateKey">����ǩ����˽Կ</param>
		/// <returns>ǩ���������</returns>
		byte[] SignData(byte[] data, CngKey privateKey);

		/// <summary>
		/// ��֤ǩ��
		/// </summary>
		/// <param name="data">ԭʼ����</param>
		/// <param name="signature">ǩ������</param>
		/// <param name="publicKey">������֤ǩ���Ĺ�Կ</param>
		/// <returns>��֤����������֤ͨ������true�����򷵻�false</returns>
		bool VerifyData(byte[] data, byte[] signature, CngKey publicKey);
	}
}
