function AppInfo(url) {
  if (url === undefined) {
    url = "http://localhost:8080";
  }
  return {
    url: url,
    ID: undefined,
    ImageName: "",
    DesiredInstances: undefined,
    IsStateless: undefined,
    Submit: function(callbackFunction) {
      var obj = new Object();
      obj.ImageName = this.ImageName;
      obj.ID = this.ID;
      obj.DesiredInstances = this.DesiredInstances;
      obj.IsStateless = this.IsStateless;
      var post = $.post(url, obj);

      post.always(function(data, status, xhr) {
        console.log("typeof param1 = " + typeof(data) + ", param2 = " + typeof(status) + ", param3 = " + typeof(xhr));
        callbackFunction(data, status, xhr);
      });
    }
  };
}

