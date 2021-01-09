using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using JWT;
using System.Net.Http;
using System.Net;
using System.Text;
using JWT.Algorithms;
using JWT.Serializers;
using System.Net.Http.Headers;
using System.Collections.Generic;
using Cylance.Code;

namespace Cylance
{
    public static class GetThreats
    {
        private const int TimeoutSecs = 1800;
        static HttpResponseMessage response = new HttpResponseMessage();
        static string jsonResponse = string.Empty;

        [FunctionName("GetThreats")]
        public static async Task<HttpResponseMessage> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            log.LogInformation("C# HTTP trigger function processed a request.");

            const string tenantId = "ba50714d-f006-47db-9420-fcc0b00666e3";
            const string appId = "d4146a43-6826-40f3-b136-67de6f996c71";
            const string appSecret = "c8710d12-083c-4c4a-98ff-0b3e5be18247";

            var utcNow = DateTimeOffset.UtcNow;
            var jwtClaims = new JwtClaims
            {
                iss = "http://cylance.com",
                jti = Guid.NewGuid().ToString(),
                iat = utcNow.ToUnixTimeSeconds(),
                exp = (utcNow).AddSeconds(1800).ToUnixTimeSeconds(),
                tid = tenantId,
                sub = appId
            };

            try
            {
                var authToken = GenerateAuthorizationToken(jwtClaims, appSecret);
                Console.WriteLine($"\n[Authorization Token]\n{authToken}\n");

                var accessToken = GenerateAccessToken(authToken);
                Console.WriteLine($"\n[Access Token]\n{accessToken}\n");
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(jsonResponse, Encoding.UTF8, "application/json")
            };
        }
        private static string GenerateAuthorizationToken(JwtClaims jwtClaims, string appSecret)
        {
            if (jwtClaims == null)
            {
                throw new ArgumentNullException(nameof(jwtClaims));
            }

            if (string.IsNullOrWhiteSpace(appSecret))
            {
                throw new ArgumentException(nameof(appSecret));
            }

            var algorithm = new HMACSHA256Algorithm();
            var serializer = new JsonNetSerializer();
            var encoder = new JwtBase64UrlEncoder();
            var jwt = new JwtEncoder(algorithm, serializer, encoder);

            return jwt.Encode(jwtClaims, appSecret);
        }

        private static async Task GenerateAccessToken(string authToken)
        {
            if (string.IsNullOrWhiteSpace(authToken))
            {
                throw new ArgumentException(nameof(authToken));
            }

            var authRequest = new AuthTokenRequest
            {
                AuthToken = authToken
            };

            using (var queryClient = new HttpClient())
            {
                queryClient.BaseAddress = new Uri(@"https://protectapi.cylance.com");
                queryClient.DefaultRequestHeaders.Accept.Clear();
                queryClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                queryClient.DefaultRequestHeaders.Add("Authorization", "Bearer " + authRequest.AuthToken);

                string _getResults = "/auth/v2/token";

                var jsonObject = new CylanceAuthRequest
                {
                    title = "Authorization Request",
                    type = "Token",
                    properties = new Properties
                    {
                        auth_token = new AuthToken
                        {
                            type = "",
                            description = ""
                        }
                    },
                    required = new List<string> {
                        authRequest.AuthToken
                    }
                };

            var content = new StringContent(JsonConvert.SerializeObject(jsonObject).ToString(), Encoding.UTF8, "application/json");
                //var content = JsonConvert.SerializeObject(tokenBody);

                var response = await queryClient.PostAsync(_getResults, content);

                var queryResult = await response.Content.ReadAsStringAsync();

                jsonResponse = JsonConvert.SerializeObject(queryResult.ToString());
            }
        }
    }


    internal sealed class AuthTokenRequest
    {
        [JsonProperty("auth_token")]
        public string AuthToken { get; set; }
    }

    internal sealed class AuthTokenResponse
    {
        [JsonProperty("access_token")]
        public string AccessToken { get; set; }
    }

    internal sealed class JwtClaims
    {
        public long exp { get; set; }
        public long iat { get; set; }
        public string iss { get; set; }
        public string sub { get; set; }
        public string jti { get; set; }
        public string tid { get; set; }
        public string scp { get; set; }
    }
}

