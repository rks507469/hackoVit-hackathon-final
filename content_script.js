console.log("chrome Extention go");

chrome.runtime.onMessage.addListener(gotMessage);

function gotMessage(message, sender, sendResponse){
    console.log(message.txt);
    if(message.txt == "malacious"){
        // we call the html page showning all the piecharts and all sayings its malacious
    }
    else{
        // we call the html page sayiny that url is clean and you're good to go!
    }
    
}