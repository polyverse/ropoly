function polysploitWidget(someDivId, someAppInfo) {
  var div = document.getElementById(someDivId);
  div.appInfo = someAppInfo;
  div.timer = undefined;
  div.interval = undefined;
  div.callback = function(){}; // noop function
  div.url = "";
  div.post = function(url){
    if ((this.interval != undefined) && (this.timer === undefined)) {
      this.timer = setInterval("document.getElementById('" + this.id + "').post();",this.interval);
      document.getElementById(this.id).post();
      return;
    }
  
    var post = $.post(this.url, this.appInfo);
    post.always(function(data, status, xhr) {
      document.getElementById(someDivId).callback(data, status, xhr);
    });
  };
  div.stop = function(){
    if ((this.interval != undefined) && (this.timer != undefined)) {
      clearInterval(this.timer);
      this.timer = undefined;
    }
  }

  return div;
}
