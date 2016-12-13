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

function statter(size) {
  var db = [];
  for (var i = 0; i < size; i++) {
    db[i] = {};
  }
  return {
    cols: {}, // hash to store all unique column names
    _cols: [],
    record: {}, // object stores values between flushes
    db: db, // fixed-size database
    init: function(size) {
      for (var i = 0; i < size; i++) {
        this.db[i] = {};
      }
    },
    inc: function(k,v) {
      this.cols[k] = k.toString();
      var match = false;
      for (var i = 0; i < this._cols.length; i++) {
        if (this._cols[i] === k.toString()) {
          match = true;
        }
      }
      if (match != true) {
        console.log("match != true");
        this._cols.push(k);
      }
      this.record[k] === undefined ? this.record[k] = v : this.record[k] += v;
    },
    gauge: function(k,v) {
      this.cols[k] = k;
      this.record[k] = v;
    },
    flush: function() {
      this.db[this.db.length] = this.record; // add record to end
      this.db.splice(0,1); // remove first record
      this.record = {}; // reset record
    },
    label: function(k, text) {
      this.cols[k] = text;
    },
    dump: function() {
      var data = [];
      var row = [];
      for (var i = 0; i < this._cols.length; i++) {
        console.log("prop = " + this._cols[i]);
        row.push(this._cols[i]);
      }
      data[data.length] = row;
      console.log(row);
      for (var i = 0; i < this.db.length; i++) {
        //console.log("i = " + i);
        row = [];
        for (var n = 0; n < this._cols.length; n++) {
          //console.log("this._cols[" + n + "] = " + this._cols[n]);
          this.db[i][(this._cols[n])] === undefined ? row.push(0) : row.push(this.db[i][(this._cols[n])]);
        }
        data[data.length] = row;
        console.log(row);
      }
      console.log("done.");
      return data;
    }
  };
}
