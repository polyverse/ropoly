function showProps(obj) {
  var result = "";
  for (var i in obj) {
    if (obj.hasOwnProperty(i)) {
      result += "." + i + " = " + obj[i] + " typeof=" + typeof(obj[i]) + "\n";
    }
  }
  return result;
}

function NewRequestBatch() {

  var batch = new Object();

  batch.ImageName = undefined;
  batch.BindingPort = undefined;

  batch.Dump = showProps;

  return batch;
}

function Statter(size) {
  size = Number(size);
  var db = [];
  //console.log(size);
  if (isNaN(size)) {
    //console.log("foo");
    size = 100;
  }
  //console.log(size);
  for (var i = 0; i < size; i++) {
    db[i] = {};
  }
  return {
    hashCols: {},
    cols: [],
    record: {}, // object stores values between flushes
    db: db, // fixed-size database
    Inc: function(k,v) {
      //k = k.toString(); v = Number(v);    
      if (this.hashCols[k] === undefined) {
        this.hashCols[k] = k;
        this.cols.push(k);
      }
      this.record[k] === undefined ? this.record[k] = v : this.record[k] += v;
    },
    Gauge: function(k,v) {
      //k = k.toString(); v = Number(v);
      if (this.hashCols[k] === undefined) {
        this.hashCols[k] = k;
        this.cols.push(k);
      }
      this.record[k] = v;
    },
    Flush: function() {
      this.db[this.db.length] = this.record; // add record to end
      this.db.splice(0,1); // remove first record
      this.record = {}; // reset record
      //console.log(this.db);
    },
    Label: function(k, text) {
      //k = k.toString(); text = text.toString();
      if (this.hashCols[k] === undefined) {
        this.cols.push(k);
      }
      this.hashCols[k] = text;
    },
    ToArray: function() {
      var data = [];
      var row = [];
      for (var i = 0; i < this.cols.length; i++) {
        //console.log("prop = " + this.cols[i]);
        row.push(this.hashCols[this.cols[i]]);
      }
      data[data.length] = row;
      //console.log(row);
      for (var i = 0; i < this.db.length; i++) {
        //console.log("i = " + i);
        row = [];
        for (var n = 0; n < this.cols.length; n++) {
          //console.log("this.cols[" + n + "] = " + this.cols[n]);
          this.db[i][(this.cols[n])] === undefined ? row.push(0) : row.push(this.db[i][(this.cols[n])]);
        }
        data[data.length] = row;
        //console.log(row);
      }
      //console.log(data);
      return data;
    }
  };
}

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
        callbackFunction(data, status, xhr);
      });
    }
  };
}
