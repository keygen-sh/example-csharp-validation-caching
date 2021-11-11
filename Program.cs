using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Utilities.Encoders;
using RestSharp;
using RestSharp.Serialization.Json;
using System;
using System.Linq;
using System.Text;
using System.IO;
using System.Collections.Generic;

class Keygen
{
  const string KEYGEN_PUBLIC_KEY = "e8601e48b69383ba520245fd07971e983d06d22c4257cfd82304601479cee788";
  const string KEYGEN_ACCOUNT_ID = "1fddcec8-8dd3-4d8d-9b16-215cac0f9b52";

  public RestClient Client = null;

  public Keygen()
  {
    Client = new RestClient("https://api.keygen.sh");
  }

  // Validate validates the provided license key, using a local file cache if available.
  public Dictionary<string, object> Validate(string licenseKey)
  {
    var cache = GetCache("validate");
    if (cache != null)
    {
      return cache;
    }

    var request = new RestRequest($"/v1/accounts/{KEYGEN_ACCOUNT_ID}/licenses/actions/validate-key", Method.POST);

    request.AddHeader("Content-Type", "application/vnd.api+json");
    request.AddHeader("Accept", "application/vnd.api+json");
    request.AddJsonBody(new
    {
      meta = new
      {
        key = licenseKey
      }
    });

    var response = Client.Execute<Dictionary<string, object>>(request);
    var ok = VerifyResponseSignature(response);
    if (!ok)
    {
      Console.WriteLine("[ERROR] [Validate] Invalid response signature!");

      Environment.Exit(1);
    }

    if (response.Data.ContainsKey("errors"))
    {
      var errors = (JsonArray) response.Data["errors"];
      if (errors != null)
      {
        Console.WriteLine("[ERROR] [Validate] An API error occurred! Status={0} Errors={1}", response.StatusCode, errors);

        Environment.Exit(1);
      }
    }

    // TODO(ezekg) Define a TTL for the cache
    SetCache("validate", response);

    return response.Data;
  }

  // VerifyResponseSignature verifies the signature of a response using Ed25519.
  private bool VerifyResponseSignature(IRestResponse response)
  {
    var parameters = GetResponseParams(response);

    return VerifyResponseSignature(
      parameters["target"],
      parameters["date"],
      parameters["digest"],
      parameters["signature"]
    );
  }

  // VerifyResponseSignature verifies the signature of the provided signing data
  // using Ed25519.
  private bool VerifyResponseSignature(string target, string date, string digest, string signature)
  {
    var signingData = $"(request-target): {target}\n";

    signingData += "host: api.keygen.sh\n";
    signingData += $"date: {date}\n";
    signingData += $"digest: {digest}";

    var signatureBytes = Convert.FromBase64String(signature);
    var signingDataBytes = Encoding.UTF8.GetBytes(signingData);
    var publicKeyBytes = Hex.DecodeStrict(KEYGEN_PUBLIC_KEY);
    var publicKey = new Ed25519PublicKeyParameters(publicKeyBytes, 0);
    var ed25519 = new Ed25519Signer();

    ed25519.Init(false, publicKey);
    ed25519.BlockUpdate(signingDataBytes, 0, signingDataBytes.Length);

    return ed25519.VerifySignature(signatureBytes);
  }

  // GetResponseParams gets a dictionary of response parameters for signature verification
  // and for caching purposes.
  private Dictionary<string, string> GetResponseParams(IRestResponse response)
  {
    var signatureHeader = response.Headers.Where(x => x.Name == "Keygen-Signature").Select(x => x.Value).FirstOrDefault().ToString();
    var digestHeader = response.Headers.Where(x => x.Name == "Digest").Select(x => x.Value).FirstOrDefault().ToString();
    var dateHeader = response.Headers.Where(x => x.Name == "Date").Select(x => x.Value).FirstOrDefault().ToString();
    var request = response.Request;
    var requestMethod = request.Method.ToString().ToLower();
    var requestUri = request.Resource;
    var requestTarget = $"{requestMethod} {requestUri}";
    var signatureParams = GetSignatureParams(signatureHeader);
    var body = response.RawBytes;
    var digest = GetDigest(body);
    var signature = signatureParams["signature"];

    return new Dictionary<string, string>()
    {
      { "signature", signature },
      { "body", Encoding.UTF8.GetString(body) },
      { "target", requestTarget },
      { "host", "api.keygen.sh" },
      { "date", dateHeader },
      { "digest", digest },
    };
  }

  // GetSignatureParams parses the Keygen-Signature header, returning a dictionary
  // of the header's parameterized values.
  private Dictionary<string, string> GetSignatureParams(string header)
  {
    var parameters = new Dictionary<string, string>();

    foreach (var parameter in header.Split(","))
    {
      var kv = parameter.Split("=", 2);
      var k = kv[0].TrimStart(char.Parse(" "));
      var v = kv[1].Trim(char.Parse("\""));

      parameters.Add(k, v);
    }

    return parameters;
  }

  // GetDigest calculates a SHA-256 digest for the provided message.
  private string GetDigest(byte[] message)
  {
    Sha256Digest sha256 = new Sha256Digest();
    sha256.BlockUpdate(message, 0, message.Length);

    byte[] hash = new byte[sha256.GetDigestSize()];
    sha256.DoFinal(hash, 0);

    var enc = Convert.ToBase64String(hash);

    return $"sha-256={enc}";
  }

  // GetCache gets the cached response data at the provided cache key. It will
  // automatically verify the integrity of the cached data.
  private Dictionary<string, object> GetCache(string key)
  {
    Dictionary<string, string> cache = null;
    try
    {
      var text = File.ReadAllText($"cache/{key}.json");

      cache = SimpleJson.DeserializeObject<Dictionary<string, string>>(text);
    }
    catch (FileNotFoundException)
    {
      Console.WriteLine("[INFO] [GetCache] Cache miss: key={0}", key);

      return null;
    }

    if (cache == null)
    {
      Console.WriteLine("[INFO] [GetCache] Cache invalid: key={0}", key);

      return null;
    }

    Console.WriteLine("[INFO] [GetCache] Cache hit: key={0}", key);

    // Verify integrity of the cached data
    var target = cache["target"];
    var body = cache["body"];
    var date = cache["date"];
    var sig = cache["signature"];

    // Recalculate the digest of the cached data
    var bytes = Encoding.UTF8.GetBytes(body);
    var digest = GetDigest(bytes);

    var ok = VerifyResponseSignature(target, date, digest, sig);
    if (!ok)
    {
      Console.WriteLine("[ERROR] [GetCache] Invalid cache signature! It has likely been tampered with.");

      Environment.Exit(1);
    }

    var data = SimpleJson.DeserializeObject<Dictionary<string, object>>(body);

    return data;
  }

  // SetCache sets the cached response data at the provided cache key
  private void SetCache(string key, IRestResponse response)
  {
    var parameters = GetResponseParams(response);
    var text = SimpleJson.SerializeObject(new
    {
      date = parameters["date"],
      target = parameters["target"],
      signature = parameters["signature"],
      body = parameters["body"],
    });

    Console.WriteLine("[INFO] [SetCache] Cache write: key={0}", key);

    File.WriteAllText($"cache/{key}.json", text);
  }
}

class Program
{
  public static void Main(string[] args)
  {
    var keygen = new Keygen();

    // Validate license using cache data when available
    var validation = keygen.Validate("C1B6DE-39A6E3-DE1529-8559A0-4AF593-V3");
    var meta = (IDictionary<string, object>) validation["meta"];

    if ((bool) meta["valid"])
    {
      Console.WriteLine("[INFO] [Main] License is valid! detail={0} code={1}", meta["detail"], meta["constant"]);
    }
    else
    {
      Console.WriteLine("[INFO] [Main] License invalid! detail={0} code={1}", meta["detail"], meta["constant"]);
    }
  }
}
