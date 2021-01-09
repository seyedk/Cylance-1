using System;
using System.Collections.Generic;
using System.Text;

namespace Cylance.Code
{
// Root myDeserializedClass = JsonConvert.DeserializeObject<Root>(myJsonResponse); 
    public class AuthToken    {
        public string type { get; set; } 
        public string description { get; set; } 
    }

    public class Properties    {
        public AuthToken auth_token { get; set; } 
    }

    public class CylanceAuthRequest
    {
        public string title { get; set; } 
        public string type { get; set; } 
        public Properties properties { get; set; } 
        public List<string> required { get; set; } 
    }
}
