﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//     Runtime Version:4.0.30319.42000
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace WindowsFormsApp5.WSAAProduccion {
    using System.Runtime.Serialization;
    using System;
    
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Runtime.Serialization", "4.0.0.0")]
    [System.Runtime.Serialization.DataContractAttribute(Name="LoginFault", Namespace="https://wsaa.afip.gov.ar/ws/services/LoginCms")]
    [System.SerializableAttribute()]
    public partial class LoginFault : object, System.Runtime.Serialization.IExtensibleDataObject, System.ComponentModel.INotifyPropertyChanged {
        
        [System.NonSerializedAttribute()]
        private System.Runtime.Serialization.ExtensionDataObject extensionDataField;
        
        [global::System.ComponentModel.BrowsableAttribute(false)]
        public System.Runtime.Serialization.ExtensionDataObject ExtensionData {
            get {
                return this.extensionDataField;
            }
            set {
                this.extensionDataField = value;
            }
        }
        
        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;
        
        protected void RaisePropertyChanged(string propertyName) {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null)) {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }
    
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    [System.ServiceModel.ServiceContractAttribute(Namespace="https://wsaa.afip.gov.ar/ws/services/LoginCms", ConfigurationName="WSAAProduccion.LoginCMS")]
    public interface LoginCMS {
        
        // CODEGEN: Generating message contract since the wrapper namespace (http://wsaa.view.sua.dvadac.desein.afip.gov) of message loginCmsRequest does not match the default value (https://wsaa.afip.gov.ar/ws/services/LoginCms)
        [System.ServiceModel.OperationContractAttribute(Action="", ReplyAction="*")]
        [System.ServiceModel.FaultContractAttribute(typeof(WindowsFormsApp5.WSAAProduccion.LoginFault), Action="", Name="fault")]
        WindowsFormsApp5.WSAAProduccion.loginCmsResponse loginCms(WindowsFormsApp5.WSAAProduccion.loginCmsRequest request);
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.ServiceModel.MessageContractAttribute(WrapperName="loginCms", WrapperNamespace="http://wsaa.view.sua.dvadac.desein.afip.gov", IsWrapped=true)]
    public partial class loginCmsRequest {
        
        [System.ServiceModel.MessageBodyMemberAttribute(Namespace="http://wsaa.view.sua.dvadac.desein.afip.gov", Order=0)]
        public string in0;
        
        public loginCmsRequest() {
        }
        
        public loginCmsRequest(string in0) {
            this.in0 = in0;
        }
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.ServiceModel.MessageContractAttribute(WrapperName="loginCmsResponse", WrapperNamespace="http://wsaa.view.sua.dvadac.desein.afip.gov", IsWrapped=true)]
    public partial class loginCmsResponse {
        
        [System.ServiceModel.MessageBodyMemberAttribute(Namespace="http://wsaa.view.sua.dvadac.desein.afip.gov", Order=0)]
        public string loginCmsReturn;
        
        public loginCmsResponse() {
        }
        
        public loginCmsResponse(string loginCmsReturn) {
            this.loginCmsReturn = loginCmsReturn;
        }
    }
    
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    public interface LoginCMSChannel : WindowsFormsApp5.WSAAProduccion.LoginCMS, System.ServiceModel.IClientChannel {
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    public partial class LoginCMSClient : System.ServiceModel.ClientBase<WindowsFormsApp5.WSAAProduccion.LoginCMS>, WindowsFormsApp5.WSAAProduccion.LoginCMS {
        
        public LoginCMSClient() {
        }
        
        public LoginCMSClient(string endpointConfigurationName) : 
                base(endpointConfigurationName) {
        }
        
        public LoginCMSClient(string endpointConfigurationName, string remoteAddress) : 
                base(endpointConfigurationName, remoteAddress) {
        }
        
        public LoginCMSClient(string endpointConfigurationName, System.ServiceModel.EndpointAddress remoteAddress) : 
                base(endpointConfigurationName, remoteAddress) {
        }
        
        public LoginCMSClient(System.ServiceModel.Channels.Binding binding, System.ServiceModel.EndpointAddress remoteAddress) : 
                base(binding, remoteAddress) {
        }
        
        [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
        WindowsFormsApp5.WSAAProduccion.loginCmsResponse WindowsFormsApp5.WSAAProduccion.LoginCMS.loginCms(WindowsFormsApp5.WSAAProduccion.loginCmsRequest request) {
            return base.Channel.loginCms(request);
        }
        
        public string loginCms(string in0) {
            WindowsFormsApp5.WSAAProduccion.loginCmsRequest inValue = new WindowsFormsApp5.WSAAProduccion.loginCmsRequest();
            inValue.in0 = in0;
            WindowsFormsApp5.WSAAProduccion.loginCmsResponse retVal = ((WindowsFormsApp5.WSAAProduccion.LoginCMS)(this)).loginCms(inValue);
            return retVal.loginCmsReturn;
        }
    }
}
