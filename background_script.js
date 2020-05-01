console.log("chrome Extention go");

chrome.browserAction.onClicked.addListener(buttonClicked)

function buttonClicked(tab){
    let msg = {
        text:"malacious"
    }
   // here we can run our algorithm for checking the malacious website
    // and then calling our extention.html page from here
    
    chrome.tabs.sendMessage(tab.id, msg);  // we call this function when we have found that url is malacious  
}