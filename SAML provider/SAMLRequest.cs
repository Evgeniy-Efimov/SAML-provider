using System;
using System.IO.Compression;
using System.IO;
using System.Text;
using System.Xml;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Deployment.Internal.CodeSigning;
using System.Security.Cryptography.Xml;

namespace Domain.Models
{
    public class SAMLRequest
    {
        private const int PROV_RSA_AES = 24;

        private SAMLParameters SAMLParameters;

        public SAMLRequest(SAMLParameters samlParameters)
        {
            SAMLParameters = samlParameters;
        }

        public string GetSSORequestUrl()
        {
            var xmlDocument = new XmlDocument();
            xmlDocument.PreserveWhitespace = true;
            using (var xmlWriter = xmlDocument.CreateNavigator().AppendChild())
            {
                xmlWriter.WriteStartElement("samlp", "AuthnRequest", "urn:oasis:names:tc:SAML:2.0:protocol");
                xmlWriter.WriteAttributeString("ID", "_" + Guid.NewGuid().ToString());
                xmlWriter.WriteAttributeString("Version", "2.0");
                xmlWriter.WriteAttributeString("ProviderName", SAMLParameters.ProviderName);
                xmlWriter.WriteAttributeString("IssueInstant", DateTime.Now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ", System.Globalization.CultureInfo.InvariantCulture));
                xmlWriter.WriteAttributeString("Destination", SAMLParameters.IdpAuthEndpoint);
                xmlWriter.WriteAttributeString("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
                xmlWriter.WriteAttributeString("AssertionConsumerServiceURL", SAMLParameters.AssertionConsumerService);

                xmlWriter.WriteStartElement("saml", "Issuer", "urn:oasis:names:tc:SAML:2.0:assertion");
                xmlWriter.WriteString(SAMLParameters.EntityId);
                xmlWriter.WriteEndElement();

                xmlWriter.WriteStartElement("samlp", "NameIDPolicy", "urn:oasis:names:tc:SAML:2.0:protocol");
                xmlWriter.WriteAttributeString("Format", SAMLParameters.NameIDFormat);
                xmlWriter.WriteAttributeString("AllowCreate", "true");
                xmlWriter.WriteEndElement();

                xmlWriter.WriteEndElement();
            }

            //sign xml
            if (SAMLParameters.IsSignSSORequest)
            {
                SignXmlDocument(ref xmlDocument);
            }

            //encode xml for redirect url parameter
            var encodedXml = string.Empty;
            using (var memoryStream = new MemoryStream())
            {
                using (var stringWriter = new StringWriter())
                {
                    using (var xmlWriter = XmlWriter.Create(stringWriter))
                    {
                        xmlDocument.WriteTo(xmlWriter);
                        xmlWriter.Flush();
                        var streamWriter = new StreamWriter(new DeflateStream(memoryStream, CompressionMode.Compress, true), new UTF8Encoding(false));
                        streamWriter.Write(stringWriter.GetStringBuilder().ToString());
                        streamWriter.Close();
                        encodedXml = Convert.ToBase64String(memoryStream.GetBuffer(), 0, (int)memoryStream.Length, Base64FormattingOptions.None);
                    }
                }
            }

            //return redirect url
            return SAMLParameters.IdpAuthEndpoint
                + (SAMLParameters.IdpAuthEndpoint.Contains("?") ? "&" : "?")
                + "SAMLRequest=" + Uri.EscapeDataString(encodedXml)
                + (string.IsNullOrWhiteSpace(SAMLParameters.RelayState) ? string.Empty : "&RelayState=" + Uri.EscapeDataString(SAMLParameters.RelayState));
        }

        public string GetSLORequestUrl(string UserID)
        {
            var xmlDocument = new XmlDocument();
            xmlDocument.PreserveWhitespace = true;

            using (var xmlWriter = xmlDocument.CreateNavigator().AppendChild())
            {
                xmlWriter.WriteStartElement("samlp", "LogoutRequest", "urn:oasis:names:tc:SAML:2.0:protocol");
                xmlWriter.WriteAttributeString("ID", "_" + Guid.NewGuid().ToString());
                xmlWriter.WriteAttributeString("Version", "2.0");
                xmlWriter.WriteAttributeString("IssueInstant", DateTime.Now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ", System.Globalization.CultureInfo.InvariantCulture));
                xmlWriter.WriteAttributeString("Destination", SAMLParameters.IdpLogoutEndpoint);
                xmlWriter.WriteAttributeString("AssertionConsumerServiceURL", SAMLParameters.AssertionConsumerService);

                xmlWriter.WriteStartElement("saml", "Issuer", "urn:oasis:names:tc:SAML:2.0:assertion");
                xmlWriter.WriteString(SAMLParameters.EntityId);
                xmlWriter.WriteEndElement();

                xmlWriter.WriteStartElement("saml", "NameID", "urn:oasis:names:tc:SAML:2.0:protocol");
                xmlWriter.WriteAttributeString("SPNameQualifier", SAMLParameters.EntityId);
                xmlWriter.WriteAttributeString("Format", SAMLParameters.LoginAttributeName);
                xmlWriter.WriteString(UserID);
                xmlWriter.WriteEndElement();

                xmlWriter.WriteEndElement();
            }

            //sign xml
            if (SAMLParameters.IsSignSLORequest)
            {
                SignXmlDocument(ref xmlDocument);
            }

            //encode xml for redirect url parameter
            var encodedXml = string.Empty;
            using (var memoryStream = new MemoryStream())
            {
                using (var stringWriter = new StringWriter())
                {
                    using (var xmlWriter = XmlWriter.Create(stringWriter))
                    {
                        xmlDocument.WriteTo(xmlWriter);
                        xmlWriter.Flush();
                        var streamWriter = new StreamWriter(new DeflateStream(memoryStream, CompressionMode.Compress, true), new UTF8Encoding(false));
                        streamWriter.Write(stringWriter.GetStringBuilder().ToString());
                        streamWriter.Close();
                        encodedXml = Convert.ToBase64String(memoryStream.GetBuffer(), 0, (int)memoryStream.Length, Base64FormattingOptions.None);
                    }
                }
            }

            //return redirect url
            return SAMLParameters.IdpLogoutEndpoint
                + (SAMLParameters.IdpLogoutEndpoint.Contains("?") ? "&" : "?")
                + "SAMLRequest=" + Uri.EscapeDataString(encodedXml);
        }

        private void SignXmlDocument(ref XmlDocument xmlDocument)
        {
            try
            {
                CryptoConfig.AddAlgorithm(typeof(RSAPKCS1SHA256SignatureDescription), SAMLParameters.RequestSignatureMethod); //http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
            }
            catch { }

            var signCertificatePath = AppDomain.CurrentDomain.BaseDirectory + SAMLParameters.SpPfxPath;

            if (!File.Exists(signCertificatePath))
                throw new Exception($"Sp pfx file doesn't exist: {signCertificatePath}");

            var signCertificate = new X509Certificate2(signCertificatePath, SAMLParameters.SpPfxPassword,
                X509KeyStorageFlags.MachineKeySet |
                X509KeyStorageFlags.PersistKeySet |
                X509KeyStorageFlags.Exportable);

            //convert key to sha256
            var exportedKeyXmlString = signCertificate.PrivateKey.ToXmlString(true);
            var key = new RSACryptoServiceProvider(new CspParameters(PROV_RSA_AES));
            key.PersistKeyInCsp = false;
            key.FromXmlString(exportedKeyXmlString);

            //set key and sign methods
            var signedXml = new SignedXml(xmlDocument);
            signedXml.SigningKey = key;
            signedXml.SignedInfo.SignatureMethod = SAMLParameters.RequestSignatureMethod;
            signedXml.SignedInfo.CanonicalizationMethod = SAMLParameters.RequestSignatureCanonicalizationMethod;

            //add reference + transform
            var reference = new Reference { Uri = string.Empty }; //Empty Uri to sign entire document
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigExcC14NTransform());
            signedXml.AddReference(reference);

            //save key info
            KeyInfo keyInfo = new KeyInfo();
            keyInfo.AddClause(new KeyInfoX509Data(signCertificate));
            signedXml.KeyInfo = keyInfo;

            //sign xml
            signedXml.ComputeSignature();
            xmlDocument.DocumentElement.InsertBefore(signedXml.GetXml(), xmlDocument.DocumentElement.LastChild);
        }
    }
}