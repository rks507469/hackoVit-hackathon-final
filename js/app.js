//This is the mechanics of the JavaScript Extension

//taking the input from the extension Page
let output;
let detected, total, undetected, checkedUrl;
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
  getData();
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
    let infomap = new Map();
    infomap.set("positives", data.positives);
    infomap.set("total", data.total);
    infomap.set("url", data.url);
    detected = parseInt(infomap.get("positives"));
    total = parseInt(infomap.get("total"));
    undetected = total - detected;
    checkedUrl = infomap.get("url");
    chartIt(detected, undetected, total);
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
// async function graphingdata() {
//   undetected = total - detected;
//     return {detected, undetected, total, checkedUrl};
// }

//technology stack

//graphing or plotting function
async function chartIt(detected, undetected, total) {
  const ctx = document.getElementById('myChart').getContext('2d');
  const myChart = new Chart(ctx, {
    type : 'doughnut',
    data :data = {
      datasets: [{
          data: [detected, undetected, total],
          backgroundColor: [
            'rgba(255, 99, 132, 1)',
            'rgba(75, 192, 192, 0.8)',
            'rgba(54, 162, 235, 0.8)'
          ],
          borderWidth: 2
        }],
      labels: [
          'Detected',
          'Undetected',
          'Total'
      ]
  }
  });
}
