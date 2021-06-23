using System.Text;
using System.Linq;

using System.Security.Cryptography;
using WebApplication2.Models;
using System.Web.Mvc;
using System;
using Newtonsoft.Json.Linq;
using System.IO;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace WebApplication2.Controllers
{
    public class HomeController : Controller
    {
        private DB_Entities _db = new DB_Entities();
        // GET: Home
        public ActionResult Index()
        {
            if (Session["idUser"] != null)
            {
                return View();
            }
            else
            {
                return RedirectToAction("Login");
            }
        }

        //GET: Register

        public ActionResult Register()
        {
            return View();
        }

        //POST: Register
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Register(User _user)
        {
            if (ModelState.IsValid)
            {
                var check = _db.Users.FirstOrDefault(s => s.Email == _user.Email);
                if (check == null)
                {
                    _user.Password = GetMD5(_user.Password);
                    _db.Configuration.ValidateOnSaveEnabled = false;
                    _db.Users.Add(_user);
                    _db.SaveChanges();
                    return RedirectToAction("Index");
                }
                else
                {
                    ViewBag.error = "Email already exists";
                    return View();
                }


            }
            return View();


        }

        public ActionResult Login()
        {
            return View();
        }



        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Login(string email, string password)
        {
            if (ModelState.IsValid)
            {


                var f_password = GetMD5(password);
                var data = _db.Users.Where(s => s.Email.Equals(email) && s.Password.Equals(f_password)).ToList();
                if (data.Count() > 0)
                {
                    //add session
                    Session["FullName"] = data.FirstOrDefault().FirstName + " " + data.FirstOrDefault().LastName;
                    Session["Email"] = data.FirstOrDefault().Email;
                    Session["idUser"] = data.FirstOrDefault().idUser;
                    return RedirectToAction("Index");
                }
                else
                {
                    ViewBag.error = "Login failed";
                    return RedirectToAction("Login");
                }
            }
            return View();
        }

        // 单登录  测试
        [HttpPost]
        public ActionResult Login_PassThrough(string sp_token)
        {
            string key = @"-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAozuJE66iwKs6gz/NSelUYM/hyrtiNMk+F0UqzqdWevE2/Cjl
UCOvPQV6T3DbOtA3u5J73kdI6PXVES+gjcVqpxAj/fgoDxDohjxz6mK2EjhtYqog
c243aDwvW5HKjAR2P/OM3+9om9ub3hF+XE8i5g78cPcqvzLrja/xzsXf5lhtqILp
AkzFccyYF1XIg7tYHzaQ/LQ/o6+g+S/yqhXY89fZRb7is9gd08Hu+h5igoqV5j9z
/lTKTngwoMgxqCnCIML+G1wwdSFIjLa1aJDk25qdi2N/irjGxcv0KeQ9JEZu0cLB
C+dP2ro33t+otbhHFit9+9a2VZ96Vawd5d5y1wIDAQABAoIBABSc7A6EOyFBfj4c
zHvM707acZT8XMZ1s1WU8nbuQsl7tInbUDnyh6qZCn0Fr2mZ6a/SK7pCHj7s7F8j
OI8uou096I2lzMk6RWLON4UdughK/+U5vqdU/8I193UE0CMmXRhuVRfiT79+2AwP
AXn+tFWBBvfs/oTulThrQ4ntCv03cZohMVEbruO1a+shH7RpGDuabXYXoPNxqO4K
YyzWUDiiSMxTPpH5aI0o27x+29VEIj/cHrBLe/ETO+ymAKNK7KbY7sgNGc3iNjio
UKphcnApCf5Dn9cbGHhON5FBTduQMhjOVuc/IKS8Nxl6Zu0d8zJqe0IsyZpoi4DO
fN100mECgYEA4qSCmdBA+dtwJTzUqsXQG3rs34YbXTy6QO8NWE3VZW/yq/xcLv77
iUxlR/gstSqw+/k2L2TenSEucYHrcrEH7JrjyUzxp1pTgOYsN3CcFGb05lMv6+wc
NVddgasSOMxnhieh7T4rlv88bMPQkG9k/wULqyCRlLsG/++3dHj+q4MCgYEAuGBX
jpk0/3MWjVCirvR1rBofGMNG4VE5ih4Tt7VqfLQyV0ZKfB0LRcGYgrZjQJRbCgbS
n6cg6xZMr2kKnEfRiME2wfQIuv/0IiIR79d5LnETRmXul92frKu4Ej+wwr0kpFV7
iAfyqYTaWXfPm7EzuGdQJpovm+AQ7ulL9uH+1x0CgYBRXY4lekZZbRZNyBDxXiLg
OrlfZd3dEzgqp6e60/aQfCg65laR6KiVGgAiXk5um+z+CPITAbuJ3ae2yFWmzzdx
EgpE8oKu+haQaBHntV3TVUMGjUbfA9z8qWjAbJIWIgvodcIEUhWEGA2xXns530P6
6ezOetrI8nwI1h6eifGj0QKBgFxgEJ4mTnJJ9BubMdbcLfSrJbdfZyzOaDi19wUM
xKx0D+DAG+NxHcu2QjYDMVkSu0Ybwv0wXALMqmEcDK/eH7IXs9qa7KDcSjGrxjbX
SySkjJaxzUeTR0PYySGDfYkkAK7BEWJHMSITqN44c/C6aIJUaMjeaUn8ih9ZDbFE
60xVAoGAPfRr850KFPTeV1IBauGDMGK5prpvEsMB/hyYEIhc35MRjxbjq+6+LA+j
xbLw8A0MfaIA2rJqQbW1qPyBMFVVE3trLCuiy4HpvkBE494YaPReOCe1XxikEp1O
8/WL24CqqkTvXA4/t1IuJY55thh5TZptUeyqsKgrbtOD8EQHsk8=
-----END RSA PRIVATE KEY-----";

            // base64 解码
            var res_array = sp_token.Split('.');
            var base64_decode_aeskey = res_array[0];
            var base64_decode_data = res_array[1];           

            //var test = @"eEDZwoh+iQoWmVWYSRM2vq3SCq9ZO3fCfs6NsrI2wlhrpaU122m1j9KiwHoXcENuoX7JGFH1uaTcSXQaGZZ4KbRJ+3BbwvT9ctpW3ea8hDNAP6kOCHmG9+YafSwN/pddQ7H7bCnrCqfr1BXfZc2xp2LrZ57puOGoAExXHWuZp23I9JRF1FwRsK3UkcaAW2qgOET1M5Luv/cOKSpIYbVS2kGvu8matPBltcoeUqG1MxP9xS5S9IRmEiXUv2HnBMCtCvjm5MbDro2mlp2WunzLM6IAtMif45RoTOdVPNh5JnX6BRCrwDHYziOLk8LbeQ49qzrl6Y//HF00TA8ogldMfQ==";
            //var base64_test = @"aTIwamFUY2YyTzNFTXFEaitncE9YclRJSUU4STVpdys2UU1kMThGN3V0Y3hSTTA0dVhKRWF6ZHpoNmtYMVVoNVZRWjJCWm00b29kMU9Fbno3UFA3VjA3a09CVHpudi9WNTdnM0dVSHJhblZzUWkzT09BaEMwWEJzNnpSZ3dhVTJNN0tOVlFjNWowMG1aUldwa2VkR3RqL29zV0ZZbmwxbzl2U3k3Z2V3cmR5b2tCbHdTUnFjYUdwZDBhOGhjU08vaDVYQ1hiRVFIeldMQVFWakNkL0lSYW1jWjZCMkFpaEVZWjdzZ0QvSlVmODJXZXdjT0ZWY1hnT3MyS1NMOE51QTd5RUdKeHd5RTlzN0E0azd0N2cyMHQ5WklQWkxXcTdnN2dyZWdTV1QrTm5TL3pHZWRjazFmTHYrMmFoZGkzK09haXpPSG5yNXgwT2l3MThndVMwbzhnPT0 =";

   
            //解密 key
            try
            {
                PemReader pr = new PemReader(new StringReader(key));
                var KeyPair = (AsymmetricCipherKeyPair)pr.ReadObject();
                RSAParameters rsaParams = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)KeyPair.Private);
                RSACryptoServiceProvider csp = new RSACryptoServiceProvider();// cspParams);
                csp.ImportParameters(rsaParams);

                var bytesToDecrypt = Convert.FromBase64String(base64_decode_aeskey);
                var key_bytes = csp.Decrypt(bytesToDecrypt, RSAEncryptionPadding.Pkcs1);

                var keystr = Encoding.UTF8.GetString(key_bytes);

                //解密 内容
                string plaintext = null;

                RijndaelManaged rijAlg = new RijndaelManaged();

                    //Settings  
                rijAlg.Mode = CipherMode.CBC;
                rijAlg.Padding = PaddingMode.PKCS7;
                rijAlg.FeedbackSize = 128;


                var keybytes = Encoding.UTF8.GetBytes(keystr);
                var iv = keybytes;

                rijAlg.Key = keybytes;
                rijAlg.IV = iv;                

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(Convert.FromBase64String(base64_decode_data)))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }                
                
                // 解析 内容
                JObject o = JObject.Parse(plaintext);

                //check timestamp
                var current_timestamp = new DateTimeOffset(DateTime.UtcNow).ToUnixTimeMilliseconds();

                if (current_timestamp> (long)o["expiration"])
                {
                    throw new Exception("token expired");
                }        
                
                //add session
                Session["FullName"] = o["FirstName"].ToString() + o["LastName"];
                Session["Email"] = o["Email"];
                Session["idUser"] = o["SID"];
            }
            catch (Exception e)
            {
                ViewBag.error = "Login failed"+ e.Message;
                return RedirectToAction("Login");
            }    

            return RedirectToAction("Index");
        }        

        //Logout
        public ActionResult Logout()
        {
            Session.Clear();//remove session
            return RedirectToAction("Login");
        }



        //create a string MD5
        public static string GetMD5(string str)
        {
            MD5 md5 = new MD5CryptoServiceProvider();
            byte[] fromData = Encoding.UTF8.GetBytes(str);
            byte[] targetData = md5.ComputeHash(fromData);
            string byte2String = null;

            for (int i = 0; i < targetData.Length; i++)
            {
                byte2String += targetData[i].ToString("x2");

            }
            return byte2String;
        }

    }
}