using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Web;
using System.Xml;

namespace SAML_provider
{
    public class SAMLResponse
    {
        private SAMLParameters SAMLParameters;
        private string SAMLResponseRawData;

        private const string AssertionsNodeName = "<Assertion";

        //abbreviations of xml namespaces 
        private Dictionary<string, string> SAMLnamespaces = new Dictionary<string, string>()
        {
            { "saml", "urn:oasis:names:tc:SAML:2.0:assertion" },
            { "samlp", "urn:oasis:names:tc:SAML:2.0:protocol" },
            { "xenc", "http://www.w3.org/2001/04/xmlenc#" },
            { "ds", "http://www.w3.org/2000/09/xmldsig#" }
        };

        public SAMLResponse(SAMLParameters samlParameters, string samlResponseRawData)
        {
            SAMLParameters = samlParameters;
            SAMLResponseRawData = samlResponseRawData;
        }

        public string GetLogin()
        {
            //get xml document from response
            if (string.IsNullOrWhiteSpace(SAMLResponseRawData))
            {
                throw new Exception("SAML response is empty");
            }

            if (SAMLResponseRawData.Contains('%'))
            {
                SAMLResponseRawData = HttpUtility.UrlDecode(SAMLResponseRawData);
            }

            var samlResponseBytes = Convert.FromBase64String(SAMLResponseRawData);
            var samlResponse = Encoding.UTF8.GetString(samlResponseBytes);

            var xmlDoc = new XmlDocument();
            xmlDoc.PreserveWhitespace = true;
            xmlDoc.XmlResolver = null;
            xmlDoc.LoadXml(samlResponse);

            var xmlNamespaceManager = new XmlNamespaceManager(xmlDoc.NameTable);

            foreach (var SAMLnamespace in SAMLnamespaces)
            {
                xmlNamespaceManager.AddNamespace(SAMLnamespace.Key, SAMLnamespace.Value);
            }

            //check response status code
            var statusCode = GetXmlNode(xmlDoc, "/samlp:Response/samlp:Status/samlp:StatusCode/@Value", xmlNamespaceManager).Value;

            if (string.IsNullOrWhiteSpace(statusCode) || !statusCode.EndsWith("status:Success"))
            {
                throw new Exception($"Identity Provider blocked authentication with status {statusCode}");
            }

            //decrypt user data using sp pfx certificate
            return GetLoginFromCipher(xmlDoc, xmlNamespaceManager);
        }

        public void ValidateLogout()
        {
            //get xml document from response
            if (string.IsNullOrWhiteSpace(SAMLResponseRawData))
            {
                throw new Exception("SAML response is empty");
            }

            if (SAMLResponseRawData.Contains('%'))
            {
                SAMLResponseRawData = HttpUtility.UrlDecode(SAMLResponseRawData);
            }

            var samlResponseBytes = Convert.FromBase64String(SAMLResponseRawData);
            var samlResponse = Encoding.UTF8.GetString(samlResponseBytes);

            var xmlDoc = new XmlDocument();
            xmlDoc.PreserveWhitespace = true;
            xmlDoc.XmlResolver = null;
            xmlDoc.LoadXml(samlResponse);

            var xmlNamespaceManager = new XmlNamespaceManager(xmlDoc.NameTable);

            foreach (var SAMLnamespace in SAMLnamespaces)
            {
                xmlNamespaceManager.AddNamespace(SAMLnamespace.Key, SAMLnamespace.Value);
            }

            //check response status code
            var statusCode = GetXmlNode(xmlDoc, "/samlp:LogoutResponse/samlp:Status/samlp:StatusCode/@Value", xmlNamespaceManager).Value;

            if (string.IsNullOrWhiteSpace(statusCode) || !statusCode.EndsWith("status:Success"))
            {
                throw new Exception($"Identity Provider blocked logout with status {statusCode}");
            }
        }

        private string AesDecrypt(byte[] cipherValueData, byte[] aesKey)
        {
            try
            {
                if (cipherValueData == null || cipherValueData.Length <= 0)
                    throw new ArgumentNullException("Cipher value is empty");

                if (aesKey == null || aesKey.Length < 16)
                    throw new ArgumentNullException("Aes key is empty");

                var aesIV = aesKey.Take(16).ToArray();
                using (var memoryStream = new MemoryStream())
                {
                    using (var aesManaged = new AesManaged())
                    {
                        aesManaged.Key = aesKey;
                        aesManaged.IV = aesIV;
                        aesManaged.Padding = PaddingMode.ISO10126;
                        using (var cryptoStream = new CryptoStream(memoryStream, aesManaged.CreateDecryptor(), CryptoStreamMode.Write))
                        {
                            cryptoStream.Write(cipherValueData, 0, cipherValueData.Length);
                            cryptoStream.Close();
                            return Encoding.UTF8.GetString(memoryStream.ToArray());
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"Can't decrypt cipher: {ex.Message}");
            }
        }

        private string GetLoginFromCipher(XmlDocument xmlDoc, XmlNamespaceManager xmlNamespaceManager)
        {
            try
            {
                var spCertificatePath = AppDomain.CurrentDomain.BaseDirectory + SAMLParameters.SpPfxPath;

                if (!File.Exists(spCertificatePath))
                    throw new Exception($"Sp pfx file doesn't exist: {spCertificatePath}");

                var spCertificate = new X509Certificate2(spCertificatePath, SAMLParameters.SpPfxPassword,
                    X509KeyStorageFlags.MachineKeySet |
                    X509KeyStorageFlags.PersistKeySet |
                    X509KeyStorageFlags.Exportable);
                var cipherKey = GetXmlNode(xmlDoc, "//xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue", xmlNamespaceManager).InnerText;
                var cipherValue = GetXmlNode(xmlDoc, "//xenc:EncryptedData/xenc:CipherData/xenc:CipherValue", xmlNamespaceManager).InnerText;

                var assertions = AesDecrypt(Convert.FromBase64String(cipherValue), spCertificate.GetRSAPrivateKey().Decrypt(Convert.FromBase64String(cipherKey), RSAEncryptionPadding.OaepSHA1));
                var xmlAssertions = new XmlDocument();
                xmlAssertions.LoadXml(assertions.Substring(assertions.IndexOf(AssertionsNodeName)));

                var loginNode = GetXmlNode(xmlAssertions, $"//saml:AttributeStatement/saml:Attribute[@Name='{SAMLParameters.LoginAttributeName}']/saml:AttributeValue", xmlNamespaceManager);
                var login = loginNode?.InnerText;

                if (string.IsNullOrWhiteSpace(login))
                {
                    throw new Exception("Login not found in SAML response");
                }

                return login;
            }
            catch (Exception ex)
            {
                throw new Exception($"Can't get login: {ex.Message}");
            }
        }

        private XmlNode GetXmlNode(XmlDocument xmlDoc, string xpath, XmlNamespaceManager xmlNamespaceManager)
        {
            try
            {
                var xmlNode = xmlDoc.SelectSingleNode(xpath, xmlNamespaceManager);

                if (xmlNode == null)
                    throw new Exception("xml node is null");

                return xmlNode;
            }
            catch (Exception ex)
            {
                throw new Exception($"Can't get node using path {xpath}: {ex.Message}");
            }
        }
    }
}
