using System;
using System.Text;
using System.Windows.Forms;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Pkcs;

namespace WindowsFormsApp5
{

    

        public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            X509Certificate2 Cert = new X509Certificate2("c:\\certp12.p12","935");
          
            


            string msg = "<loginTicketRequest version=\"1.0\"><header>"+
                //"<source>cn=FePrueba,ou=facturacion,o=feprueba,c=ar,serialNumber=CUIT 20318079359</source>" +
                             "<destination>cn=wsaahomo,o=afip,c=ar,serialNumber=CUIT 20318079359</destination>" +
                "<uniqueId>43255</uniqueId><generationTime>2019-06-03T17:05:00-03:00</generationTime>" +
                    "<expirationTime>2019-06-03T18:00:00-03:00</expirationTime></header><service>wsfe</service></loginTicketRequest>";

            byte[] msg2 = CertificadosX509Lib.FirmaBytesMensaje(Encoding.ASCII.GetBytes(msg),Cert);


            ar.gov.afip.wsaahomo.LoginCMSService S = new ar.gov.afip.wsaahomo.LoginCMSService();
            
            S.loginCms(Convert.ToBase64String(msg2));
            


            


        }

        public string EncodeTo64(string toEncode)

        {

            byte[] toEncodeAsBytes

                  = System.Text.ASCIIEncoding.ASCII.GetBytes(toEncode);

            string returnValue

                  = System.Convert.ToBase64String(toEncodeAsBytes);

            return returnValue;

        }

        private void Form1_Load(object sender, EventArgs e)
        {

        }
    }

    class CertificadosX509Lib
    {
        public static bool VerboseMode = false;

        /// <summary>
        /// Firma mensaje
        /// </summary>
        /// <param name="argBytesMsg">Bytes del mensaje</param>
        /// <param name="argCertFirmante">Certificado usado para firmar</param>
        /// <returns>Bytes del mensaje firmado</returns>
        /// <remarks></remarks>
        public static byte[] FirmaBytesMensaje(byte[] argBytesMsg, X509Certificate2 argCertFirmante)
        {
            const string ID_FNC = "[FirmaBytesMensaje]";
            try
            {
                // Pongo el mensaje en un objeto ContentInfo (requerido para construir el obj SignedCms)
                ContentInfo infoContenido = new ContentInfo(argBytesMsg);
                SignedCms cmsFirmado = new SignedCms(infoContenido);

                // Creo objeto CmsSigner que tiene las caracteristicas del firmante
                CmsSigner cmsFirmante = new CmsSigner(argCertFirmante);
                cmsFirmante.IncludeOption = X509IncludeOption.EndCertOnly;

                if (VerboseMode) Console.WriteLine(ID_FNC + "***Firmando bytes del mensaje...");

                // Firmo el mensaje PKCS #7
                cmsFirmado.ComputeSignature(cmsFirmante);

                if (VerboseMode) Console.WriteLine(ID_FNC + "***OK mensaje firmado");

                // Encodeo el mensaje PKCS #7.
                return cmsFirmado.Encode();
            }
            catch (Exception excepcionAlFirmar)
            {
                throw new Exception(ID_FNC + "***Error al firmar: " + excepcionAlFirmar.Message);
            }
        }
    }

}
