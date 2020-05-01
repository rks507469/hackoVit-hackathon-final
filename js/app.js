//This is the mechanics of the JavaScript Extension

//taking the input from the extension Page
let output;
let infomap = new Map();
//making it a complete URL

//converting it the sha65
//Sourced from : https://geraintluff.github.io/sha256/
var sha256 = function sha256(ascii) {
  function rightRotate(value, amount) {
    return (value >>> amount) | (value << (32 - amount));
  }
  var mathPow = Math.pow;
  var maxWord = mathPow(2, 32);
  var lengthProperty = "length";
  var i, j;
  var result = "";
  var words = [];
  var asciiBitLength = ascii[lengthProperty] * 8;
  var hash = (sha256.h = sha256.h || []);

  var k = (sha256.k = sha256.k || []);
  var primeCounter = k[lengthProperty];

  var isComposite = {};
  for (var candidate = 2; primeCounter < 64; candidate++) {
    if (!isComposite[candidate]) {
      for (i = 0; i < 313; i += candidate) {
        isComposite[i] = candidate;
      }
      hash[primeCounter] = (mathPow(candidate, 0.5) * maxWord) | 0;
      k[primeCounter++] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
    }
  }

  ascii += "\x80";
  while ((ascii[lengthProperty] % 64) - 56) ascii += "\x00";
  for (i = 0; i < ascii[lengthProperty]; i++) {
    j = ascii.charCodeAt(i);
    if (j >> 8) return;
    words[i >> 2] |= j << (((3 - i) % 4) * 8);
  }
  words[words[lengthProperty]] = (asciiBitLength / maxWord) | 0;
  words[words[lengthProperty]] = asciiBitLength;

  for (j = 0; j < words[lengthProperty]; ) {
    var w = words.slice(j, (j += 16));
    var oldHash = hash;
    hash = hash.slice(0, 8);

    for (i = 0; i < 64; i++) {
      var i2 = i + j;
      var w15 = w[i - 15],
        w2 = w[i - 2];
      var a = hash[0],
        e = hash[4];
      var temp1 =
        hash[7] +
        (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25)) +
        ((e & hash[5]) ^ (~e & hash[6])) +
        k[i] +
        (w[i] =
          i < 16
            ? w[i]
            : (w[i - 16] +
                (rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3)) +
                w[i - 7] +
                (rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10))) |
              0);
      var temp2 =
        (rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22)) +
        ((a & hash[1]) ^ (a & hash[2]) ^ (hash[1] & hash[2]));

      hash = [(temp1 + temp2) | 0].concat(hash);
      hash[4] = (hash[4] + temp1) | 0;
    }

    for (i = 0; i < 8; i++) {
      hash[i] = (hash[i] + oldHash[i]) | 0;
    }
  }

  for (i = 0; i < 8; i++) {
    for (j = 3; j + 1; j--) {
      var b = (hash[i] >> (j * 8)) & 255;
      result += (b < 16 ? 0 : "") + b.toString(16);
    }
  }
  return result;
};

function getInputValue() {
  let input = document.getElementById("inputBox").value;
  output = sha256(input);
  //getData();
}

//now using the the API of the virus total
async function getData() {
  let res = output;
  //variable
  let json;
  //api URL
  // const apiUrl = new URL("https://www.virustotal.com/vtapi/v2/url/report");
  //URL Parameters
  let params = {
    apikey: "c56702292505c0d8e5c0b604ed785a78d383c1c4679bcdd3eadbad8c5daee557",
    resource: res,
  };

  const proxy = "https://cors-anywhere.herokuapp.com/";
  const url = `https://www.virustotal.com/vtapi/v2/url/report?apikey=${params.apikey}&resource=${params.resource}`;
  const finalURL = proxy + url;

  $.getJSON(finalURL, function (data) {
    console.log(data);
  });

}
// //fetching the data
// const response = await fetch(apiUrl, {
//     method : 'GET',
// });

//checking the response
//   if (response.ok) {
//     json = await response.json();
//     console.log(json);
//   } else {
//     console.log("Response_Error" + response.status);
//   }

//function to iterate through the JSON file
//let fetchedData = {"scan_id": "d0e196a0c25d35dd0a84593cbae0f38333aa58529936444ea26453eab28dfc86-1588334401", "resource": "d0e196a0c25d35dd0a84593cbae0f38333aa58529936444ea26453eab28dfc86", "url": "https://www.google.com/", "response_code": 1, "scan_date": "2020-05-01 12:00:01", "permalink": "https://www.virustotal.com/url/d0e196a0c25d35dd0a84593cbae0f38333aa58529936444ea26453eab28dfc86/analysis/1588334401/", "verbose_msg": "Scan finished, scan information embedded in this object", "filescan_id": null, "positives": 0, "total": 79, "scans": {"Botvrij.eu": {"detected": false, "result": "clean site"}, "Feodo Tracker": {"detected": false, "result": "clean site"}, "CLEAN MX": {"detected": false, "result": "clean site"}, "DNS8": {"detected": false, "result": "clean site"}, "NotMining": {"detected": false, "result": "unrated site"}, "VX Vault": {"detected": false, "result": "clean site"}, "securolytics": {"detected": false, "result": "clean site"}, "Tencent": {"detected": false, "result": "clean site"}, "MalwarePatrol": {"detected": false, "result": "clean site"}, "MalSilo": {"detected": false, "result": "clean site"}, "Comodo Valkyrie Verdict": {"detected": false, "result": "clean site"}, "PhishLabs": {"detected": false, "result": "unrated site"}, "EmergingThreats": {"detected": false, "result": "clean site"}, "Sangfor": {"detected": false, "result": "clean site"}, "K7AntiVirus": {"detected": false, "result": "clean site"}, "Spam404": {"detected": false, "result": "clean site"}, "Virusdie External Site Scan": {"detected": false, "result": "clean site"}, "Artists Against 419": {"detected": false, "result": "clean site"}, "IPsum": {"detected": false, "result": "clean site"}, "Cyren": {"detected": false, "result": "clean site"}, "Quttera": {"detected": false, "result": "clean site"}, "CINS Army": {"detected": false, "result": "clean site"}, "AegisLab WebGuard": {"detected": false, "result": "clean site"}, "MalwareDomainList": {"detected": false, "result": "clean site", "detail": "http://www.malwaredomainlist.com/mdl.php?search=www.google.com"}, "Lumu": {"detected": false, "result": "clean site"}, "zvelo": {"detected": false, "result": "clean site"}, "Google Safebrowsing": {"detected": false, "result": "clean site"}, "Kaspersky": {"detected": false, "result": "clean site"}, "BitDefender": {"detected": false, "result": "clean site"}, "GreenSnow": {"detected": false, "result": "clean site"}, "G-Data": {"detected": false, "result": "clean site"}, "OpenPhish": {"detected": false, "result": "clean site"}, "Malware Domain Blocklist": {"detected": false, "result": "clean site"}, "AutoShun": {"detected": false, "result": "unrated site"}, "Trustwave": {"detected": false, "result": "clean site"}, "Web Security Guard": {"detected": false, "result": "clean site"}, "CyRadar": {"detected": false, "result": "clean site"}, "desenmascara.me": {"detected": false, "result": "clean site"}, "ADMINUSLabs": {"detected": false, "result": "clean site"}, "Malwarebytes hpHosts": {"detected": false, "result": "clean site"}, "Dr.Web": {"detected": false, "result": "clean site"}, "AlienVault": {"detected": false, "result": "clean site"}, "Emsisoft": {"detected": false, "result": "clean site"}, "Spamhaus": {"detected": false, "result": "clean site"}, "malwares.com URL checker": {"detected": false, "result": "clean site"}, "Phishtank": {"detected": false, "result": "clean site"}, "EonScope": {"detected": false, "result": "clean site"}, "Malwared": {"detected": false, "result": "clean site"}, "Avira": {"detected": false, "result": "clean site"}, "Cisco Talos IP Blacklist": {"detected": false, "result": "clean site"}, "CyberCrime": {"detected": false, "result": "clean site"}, "Antiy-AVL": {"detected": false, "result": "clean site"}, "Forcepoint ThreatSeeker": {"detected": false, "result": "clean site"}, "SCUMWARE.org": {"detected": false, "result": "clean site"}, "Certego": {"detected": false, "result": "clean site"}, "Yandex Safebrowsing": {"detected": false, "result": "clean site", "detail": "http://yandex.com/infected?l10n=en&url=https://www.google.com/"}, "ESET": {"detected": false, "result": "clean site"}, "Threatsourcing": {"detected": false, "result": "clean site"}, "URLhaus": {"detected": false, "result": "clean site"}, "SecureBrain": {"detected": false, "result": "clean site"}, "Nucleon": {"detected": false, "result": "clean site"}, "PREBYTES": {"detected": false, "result": "clean site"}, "Sophos": {"detected": false, "result": "unrated site"}, "Blueliv": {"detected": false, "result": "clean site"}, "BlockList": {"detected": false, "result": "clean site"}, "Netcraft": {"detected": false, "result": "unrated site"}, "CRDF": {"detected": false, "result": "clean site"}, "ThreatHive": {"detected": false, "result": "clean site"}, "BADWARE.INFO": {"detected": false, "result": "clean site"}, "FraudScore": {"detected": false, "result": "clean site"}, "Quick Heal": {"detected": false, "result": "clean site"}, "Rising": {"detected": false, "result": "clean site"}, "StopBadware": {"detected": false, "result": "unrated site"}, "Sucuri SiteCheck": {"detected": false, "result": "clean site"}, "Fortinet": {"detected": false, "result": "clean site"}, "StopForumSpam": {"detected": false, "result": "clean site"}, "ZeroCERT": {"detected": false, "result": "clean site"}, "Baidu-International": {"detected": false, "result": "clean site"}, "Phishing Database": {"detected": false, "result": "clean site"}}}
function jsonParsing(fetchedData) {
    infomap.set("positives", fetchedData.positives);
    infomap.set("total", fetchedData.total);
    infomap.set("url", fetchedData.url);
    console.log(infomap.get("positives"));
    console.log(infomap.get("total"));
    console.log(infomap.get("url"));
}
