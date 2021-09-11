public class RC4Encryptor : IDisposable
{

    private byte[] _s_encrypt = null;
    private byte[] _s_decrypt = null;
    private byte[] _password = null;
    private byte[] _iv = null;
    private int _encrypt_offset_i = 0;
    private int _decrypt_offset_i = 0;
    private int _encrypt_offset_j = 0;
    private int _decrypt_offset_j = 0;


    public IEncryptor Clone()
    {
        return new RC4Encryptor(_password, _iv);
    }

    public void Dispose()
    {
        _s_encrypt = null;
        _s_decrypt = null;
        _password = null;
        _iv = null;
    }

    public byte[] Key => _password;

    public RC4Encryptor(byte[] password, byte[] iv)
    {
        _password = password;
        _iv = iv;
        _s_encrypt = Init();
        _s_decrypt = new byte[256];
        _s_encrypt.CopyTo(_s_decrypt, 0);
    }
    public RC4Encryptor(string password, string iv) 
        : this(Convert.FromBase64String(password), Convert.FromBase64String(iv))
    {
    }
    public RC4Encryptor(string password)
        : this(Convert.FromBase64String(password), null)
    {
    }

    private byte[] Init()
    {
        byte j = 0;
        int len = _password.Length;
        byte[] k = new byte[256];
        byte[] s = new byte[256];
        int i;
        for (i = 0; i < 256; i++)
        {
            s[i] = (byte)i;
            k[i] = _password[i % len];
        }
        for (i = 0; i < 256; i++)
        {
            j = (byte)((j + s[i] + k[i]) & 0xff);
            byte tmp = s[i];
            s[i] = s[j];//交换s[i]和s[j]
            s[j] = tmp;
        }
        return s;
    }

    private void ProcessEncrypt(byte[] buffer, int offset, int count)
    {
        int i = 0, j = 0, t = 0,k = 0;
        byte tmp;
        int end_offset = offset + count;
        byte[] s = _s_encrypt;
        for (k = offset; k < end_offset; k++)
        {
            i = _encrypt_offset_i = (_encrypt_offset_i + 1) & 0xff;
            j = _encrypt_offset_j = (_encrypt_offset_j + s[i]) & 0xff;
            tmp = s[i];
            s[i] = s[j];//交换s[x]和s[y]
            s[j] = tmp;
            t = (s[i] + s[j]) & 0xff;
            buffer[k] ^= s[t];
        }
    }
    private void ProcessDecrypt(byte[] buffer, int offset, int count)
    {
        int i = 0, j = 0, t = 0, k = 0;
        byte tmp;
        int end_offset = offset + count;
        byte[] s = _s_decrypt;
        for (k = offset; k < end_offset; k++)
        {
            i = _decrypt_offset_i =  (_decrypt_offset_i + 1) & 0xff;
            j = _decrypt_offset_j = (_decrypt_offset_j + s[i]) & 0xff;
            tmp = s[i];
            s[i] = s[j];//交换s[x]和s[y]
            s[j] = tmp;
            t = (s[i] + s[j]) & 0xff;
            buffer[k] ^= s[t];
        }
    }

    public void Encrypt(byte[] buffer, int offset, int count)
    {
        ProcessEncrypt(buffer, offset, count);
    }
    public void Decrypt(byte[] buffer, int offset, int count)
    {
        ProcessDecrypt(buffer, offset, count);
    }
}
