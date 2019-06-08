using System;
using System.Text;
using System.Windows.Forms;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Pkcs;
using System.Xml;


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
                             //"<source>cn=FePrueba,ou=facturacion,o=FePrueba,c=ar,serialNumber=CUIT 20318079359</source>" +
                             "<destination>cn=wsaa,o=afip,c=ar,serialNumber=CUIT 33693450239</destination>" +
                "<uniqueId>43255</uniqueId><generationTime>" + DateTime.Now.Year + "-0" + DateTime.Now.Month + "-0" + DateTime.Now.Day + "T0" + DateTime.Now.Hour + ":" + DateTime.Now.Minute + ":00-03:00</generationTime>" +
                    "<expirationTime>2019-06-04T05:00:00-03:00</expirationTime></header><service>wsmtxca</service></loginTicketRequest>";

            byte[] msg2 = CertificadosX509Lib.FirmaBytesMensaje(Encoding.ASCII.GetBytes(msg),Cert);


            //ar.gov.afip.wsaahomo.LoginCMSService S = new ar.gov.afip.wsaahomo.LoginCMSService();
            WSAAProduccion.LoginCMSClient Login = new WSAAProduccion.LoginCMSClient();
            
            //S.Url = "https://wsaa.afip.gov.ar/ws/services/LoginCms";
           String Response =  Login.loginCms(Convert.ToBase64String(msg2));

            XmlDocument XML = new XmlDocument();
            XML.LoadXml(Response);
            //WSMTXCAProduccion.AuthRequestType ART = new WSMTXCAProduccion.AuthRequestType();
            ar.gob.afip.serviciosjava.AuthRequestType ART = new ar.gob.afip.serviciosjava.AuthRequestType();


            //AUTH REQUEST DE AUTORIZACION
            ART.cuitRepresentada = 20318079359;
            ART.sign = XML.GetElementsByTagName("sign")[0].InnerText;
            ART.token = XML.GetElementsByTagName("token")[0].InnerText;

            //Instanciacion del mtx
            ar.gob.afip.serviciosjava.MTXCAService S = new ar.gob.afip.serviciosjava.MTXCAService();
            //Instanciacion de no se que carajo es esto
            ar.gob.afip.serviciosjava.CodigoDescripcionType DT = new ar.gob.afip.serviciosjava.CodigoDescripcionType();
            //Consulta de tipos comprobantes 
            ar.gob.afip.serviciosjava.CodigoDescripcionType[] tipos = S.consultarTiposComprobante(ART,out DT);

            

            
           

           

            
            
            
            //prueba 
            
            
            
            
            
            
            
            
            





            MessageBox.Show(XML.GetElementsByTagName("token")[0].InnerText);
            MessageBox.Show(XML.GetElementsByTagName("sign")[0].InnerText);

           





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
