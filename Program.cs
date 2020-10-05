using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Threading;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.Binder;
using Microsoft.Extensions.Configuration.EnvironmentVariables;
using Microsoft.Extensions.Configuration.FileExtensions;
using Microsoft.Extensions.Configuration.Json;
using Newtonsoft.Json;
using QRCoder;

namespace MFAUsingResourceOwner {

    class Program {
        public static IConfiguration config;

        private static string accessToken;
        private static string useremail;

        public static string userpassword { get; private set; }
        public static string mfa_requiredToken { get; private set; }

        static void Main (string[] args) {

            var builder = new ConfigurationBuilder ()
                .SetBasePath (Directory.GetCurrentDirectory ())
                .AddJsonFile ("appsettings.json", true, true)
                .AddEnvironmentVariables ();
            config = builder.Build ();

            Menu ();

        }

        public static void Menu () {
            Console.WriteLine (" 1 : Login  ");
            Console.WriteLine (" 2 : Sign up ");
            Console.WriteLine (" 3 : List authenticator (Required to run login steps first)");

            Console.Write ("Enter option : ");
            string input = Console.ReadLine ();

            if (input == "1") {
                login (useremail, userpassword);
            } else if (input == "2") {
                SignUp ();
            } else if (input == "3") {
                listAuthenticator ();
            }

        }

        private static void SignUp () {
            Console.Write ("Enter Email : ");
            string email = Console.ReadLine ();
            Console.Write ("Enter password : ");
            string password = Console.ReadLine ();
            string url = $"https://{config["domain"]}/dbconnections/signup";

            var pairs = new List<KeyValuePair<string, string>> {
                    new KeyValuePair<string, string> ("client_id", config["client_id"]),
                    new KeyValuePair<string, string> ("client_secret", config["client_secret"]),
                    new KeyValuePair<string, string> ("email", email),
                    new KeyValuePair<string, string> ("password", password),
                    new KeyValuePair<string, string> ("connection", "db")
                };
            var content = new FormUrlEncodedContent (pairs);
            using (HttpClient client = new HttpClient ()) {
                var response = client.PostAsync (url, content).Result;
                var responseBody = response.Content.ReadAsStringAsync ().Result;
                Console.WriteLine ("=========Signup response============");
                Console.WriteLine (responseBody);
                Console.WriteLine ("==========Sign up End==========");
            }
            Console.WriteLine ("Please log in");
            login (email, password);
        }

        private static void login (string email, string password) {

            if (string.IsNullOrEmpty (email) && string.IsNullOrEmpty (password)) {
                Console.Write ("Enter email : ");
                useremail = Console.ReadLine ();
                Console.Write ("Enter password : ");
                userpassword = Console.ReadLine ();
            } else {
                useremail = email;
                userpassword = password;
            }
            // var body = new AuthRequest {
            //    client_id = config["client_id"],
            //    client_secret = config["client_secret"],
            //     realm = "Username-Password-Authentication",
            //    grant_type = "http://auth0.com/oauth/grant-type/password-realm",
            //    audience = "https://tanver.au.auth0.com/api/v2/",
            //    scope = "openid read:current_user update:current_user_metadata",
            //    username = useremail,
            //    password = userpassword
            //};

            var pair = new List<KeyValuePair<string, string>> {
                    new KeyValuePair<string, string> ("client_id", config["client_id"]),
                    new KeyValuePair<string, string> ("client_secret", config["client_secret"]),
                    new KeyValuePair<string, string> ("realm", "db"),
                    new KeyValuePair<string, string> ("grant_type", "http://auth0.com/oauth/grant-type/password-realm"),
                    new KeyValuePair<string, string> ("audience", $"https://{config["domain"]}/api/v2/"),
                    new KeyValuePair<string, string> ("scope", "openid read:current_user update:current_user_metadata"),
                    new KeyValuePair<string, string> ("username", useremail),
                    new KeyValuePair<string, string> ("password", userpassword)
                };
            var content = new FormUrlEncodedContent (pair);

            var url = $"https://{config["domain"]}/oauth/token";
            using (var client = new HttpClient ()) {

                var response = client.PostAsync (url, content).Result;
                var responseBody = response.Content.ReadAsStringAsync ().Result;
                var j = JsonConvert.DeserializeObject<AuthResponse> (responseBody);
                mfa_requiredToken = j.mfa_token;

                System.Console.WriteLine ("=======Login Response======");
                System.Console.WriteLine (responseBody);
                if (j.error == "mfa_required") {
                    challange ();
                }
            }
        }

        private static void challange () {
            var pair = new List<KeyValuePair<string, string>> {
                    new KeyValuePair<string, string> ("mfa_token", mfa_requiredToken),
                    new KeyValuePair<string, string> ("challenge_type", "oob otp"),
                    new KeyValuePair<string, string> ("client_id", config["client_id"]),
                    new KeyValuePair<string, string> ("client_secret", config["client_secret"])
                };
            var content = new FormUrlEncodedContent (pair);
            string url = $"https://{config["domain"]}/mfa/challenge";
            using (var client = new HttpClient ()) {
                //  client.DefaultRequestHeaders.Authorization= new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer",)
                var response = client.PostAsync (url, content).Result;
                var responseString = response.Content.ReadAsStringAsync ().Result;
                var j = JsonConvert.DeserializeObject<ChalangeResponse> (responseString);
                Console.WriteLine ("=============Challange ==========");
                Console.WriteLine (responseString);

                Console.WriteLine ("===========================");

                if (j.error == "association_required") {
                    Associate ();
                }

                if (!string.IsNullOrEmpty (j.challenge_type)) {
                    Console.WriteLine ("Choose Authenticator option ");
                    Console.WriteLine (" 1 : Otp");
                    Console.Write ("Enter your option :");
                    string input = Console.ReadLine ();
                    if (input == "1") {
                        verifyOtpCode ();
                    }

                }
            }
        }
        private static void Associate () {
            var authenticator_types = new string[] { "otp" };

            var body = new AssociationBody {
                client_id = config["client_id"],
                client_secret = config["client_secret"],
                authenticator_types = new List<string> {
                "otp"
                }
            };
            var content = JsonConvert.SerializeObject (body);
            var stringContent = new StringContent (content, Encoding.UTF8, "application/json");
            Console.WriteLine (mfa_requiredToken);
            string url = $"https://{config["domain"]}/mfa/associate";
            using (var client = new HttpClient ()) {
                client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue ("Bearer", mfa_requiredToken);
                var response = client.PostAsync (url, stringContent).Result;
                var responseString = response.Content.ReadAsStringAsync ().Result;
                var j = JsonConvert.DeserializeObject<AssociationResponse> (responseString);
                Console.WriteLine ("============= Association ==========");
                Console.WriteLine (responseString);
                Console.WriteLine ("===========================");
                if (j.barcode_uri != null) {
                   // generateQrCode (j.barcode_uri);
                    verifyOtpCode ();
                }

            }
        }

        private static void verifyOtpCode () {
            Console.Write ("Enter otp code : ");
            string otp_code = Console.ReadLine ();
            var body = new OtpVerification {
                grant_type = "http://auth0.com/oauth/grant-type/mfa-otp",
                client_id = config["client_id"],
                client_secret = config["client_secret"],
                mfa_token = mfa_requiredToken,
                otp = otp_code
            };
            var content = JsonConvert.SerializeObject (body);
            var stringContent = new StringContent (content, Encoding.UTF8, "application/json");

            var url = $"https://{config["domain"]}/oauth/token";
            using (var http = new HttpClient ()) {
                http.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue ("Bearer", mfa_requiredToken);
                var response = http.PostAsync (url, stringContent).Result;
                var responseContent = response.Content.ReadAsStringAsync ().Result;
                var j = JsonConvert.DeserializeObject<OtpVerficationResponse> (responseContent);
                accessToken = j.access_token;
                Console.WriteLine ("===========Verify otp response =========");
                Console.WriteLine (responseContent);
                Console.WriteLine ("=====================");
            }
            // Console.WriteLine("===============Well done=========");
            // Console.WriteLine("Choose option");
            // Console.WriteLine(" 1 : List authenticator ");
            // string input = Console.ReadLine();
            // if (input == "1")
            // {
            //     listAuthenticator();
            // }

        }
        private static void generateQrCode (string qrcode) {
            QRCodeGenerator qrGenerator = new QRCodeGenerator ();
            QRCodeData qrCodeData = qrGenerator.CreateQrCode (qrcode, QRCodeGenerator.ECCLevel.Q);
            QRCode qrCode = new QRCode (qrCodeData);
            Bitmap qrCodeImage = qrCode.GetGraphic (20);
            // Console.WriteLine(qrCodeImage);
        }

        private static void listAuthenticator () {
            Console.WriteLine ("===List authenticator requires to login with  enroll and read:authenticator scope or claim===");
            loginWithAuthenticatorClaim (useremail, userpassword);
            requestListOfAuthenticator ();
        }

        private static void requestListOfAuthenticator () {
            var uri = $"https://{config["domain"]}/mfa/authenticators";
            using (var client = new HttpClient ()) {
                client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue ("Bearer", accessToken);

                var response = client.GetAsync (uri).Result;
                var responseContent = response.Content.ReadAsStringAsync ().Result;
                Console.WriteLine ("=============List of Authenticators==========");
                Console.WriteLine (responseContent);
            }
        }

        private static void loginWithAuthenticatorClaim (string email, string password) {
            if (string.IsNullOrEmpty (email) && string.IsNullOrEmpty (password)) {
                Console.Write ("Enter email : ");
                useremail = Console.ReadLine ();
                Console.Write ("Enter password : ");
                userpassword = Console.ReadLine ();
            } else {
                useremail = email;
                userpassword = password;
            }

            var pair = new List<KeyValuePair<string, string>> {
                    new KeyValuePair<string, string> ("client_id", config["client_id"]),
                    new KeyValuePair<string, string> ("client_secret", config["client_secret"]),
                    new KeyValuePair<string, string> ("realm", "Username-Password-Authentication"),
                    new KeyValuePair<string, string> ("grant_type", "http://auth0.com/oauth/grant-type/password-realm"),
                    new KeyValuePair<string, string> ("audience", $"https://{config["domain"]}/mfa/"),
                    new KeyValuePair<string, string> ("scope", "enroll read:authenticators remove:authenticators"),
                    new KeyValuePair<string, string> ("username", useremail),
                    new KeyValuePair<string, string> ("password", userpassword)
                };
            // Console.WriteLine("==========User credentials========");
            // Console.WriteLine(useremail + userpassword);
            var content = new FormUrlEncodedContent (pair);
            var url = $"https://{config["domain"]}/oauth/token";
            using (var client = new HttpClient ()) {
                var response = client.PostAsync (url, content).Result;
                var responseBody = response.Content.ReadAsStringAsync ().Result;
                var j = JsonConvert.DeserializeObject<AuthResponse> (responseBody);
                mfa_requiredToken = j.mfa_token;

                System.Console.WriteLine ("=======Login Response======");
                System.Console.WriteLine (responseBody);
                if (j.error == "mfa_required") {
                    challange ();
                }
            }

        }

        internal class AuthRequest {
            public string grant_type { get; set; }
            public string username { get; set; }
            public string password { get; set; }
            public string audience { get; set; }
            public string scope { get; set; }
            public string client_id { get; set; }
            public string client_secret { get; set; }
            public string realm { get; set; }
        }
        internal class AuthResponse {
            public string error { get; set; }
            public string error_description { get; set; }
            public string mfa_token { get; set; }
        }
        internal class ChalangeResponse {
            public string error { get; set; }
            public string error_description { get; set; }
            public string challenge_type { get; set; }
        }

        internal class AssociationResponse {
            public string secret { get; set; }
            public string barcode_uri { get; set; }
            public string authenticator_type { get; set; }
        }

        internal class RequestAccessTokenBody {
            public string client_id { get; set; }
            public string client_secret { get; set; }
            public string realm { get; set; }
            public string grant_type { get; set; }
            public string audience { get; set; }
            public string scope { get; set; }
            public string username { get; set; }
            public string password { get; set; }
        }

        internal class AssociationBody {
            public string client_id { get; set; }
            public string client_secret { get; set; }

            public List<string> authenticator_types { get; set; }
        }

        internal class OtpVerification {
            public string grant_type { get; set; }
            public string client_id { get; set; }
            public string client_secret { get; set; }
            public string mfa_token { get; set; }
            public string otp { get; set; }
        }

        internal class ListAuthenticator {
            public string grant_type { get; set; }
            public string client_id { get; set; }
            public string client_secret { get; set; }
            public string mfa_token { get; set; }
            public string otp { get; set; }
        }
        internal class OtpVerficationResponse {
            public string access_token { get; set; }
            public string id_token { get; set; }
            public string scope { get; set; }
        }
    }
}