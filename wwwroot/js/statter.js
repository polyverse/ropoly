function Statter(rows) {
  size = Number(rows);
  var db = [];
  
  if (isNaN(size)) {
    console.log("Warning: no rows specified in Statter constructor; defaulting to 10 rows.");
    size = 10;
  }

  // initialize array with empty records
  for (var i = 0; i < rows; i++) {
    db[i] = {};
  }
  return {
    hashCols: {},
    cols: [],
    record: {}, // object stores values between flushes
    db: db, // fixed-size database
    Inc: function(k,v) {
      // if the key doesn't exist in hash, add to hash and add dimension to current record.    
      if (this.hashCols[k] === undefined) {
        this.hashCols[k] = k;
        this.cols.push(k);
      }
      // set or increment the property value
      this.record[k] === undefined ? this.record[k] = v : this.record[k] += v;
    },
    Gauge: function(k,v) {
      // if the key doesn't exist in hash, add to hash and add dimension to current record.
      if (this.hashCols[k] === undefined) {
        this.hashCols[k] = k;
        this.cols.push(k);
      }
      // set the property value
      this.record[k] = v;
    },
    Flush: function() {
      // shift records based on fifo
      this.db[this.db.length] = this.record; // add record to end
      this.db.splice(0,1); // remove first record
      this.record = {}; // reset record
    },
    Label: function(k, text) {
      if (this.hashCols[k] != undefined) {
        this.hasCols[k] = text;
      } else {
        console.log("Warning: didn't find key '" + k + "'; not setting label (value) to '" + text + "'");
      }
    },
    ToArray: function() {
      var data = [];
      var row = [];

      // first row contains column headers
      for (var i = 0; i < this.cols.length; i++) {
        row.push(this.hashCols[this.cols[i]]);
      }
      data[0] = row;

      for (var i = 0; i < this.db.length; i++) {
        row = [];
        for (var n = 0; n < this.cols.length; n++) {
          this.db[i][(this.cols[n])] === undefined ? row.push(0) : row.push(this.db[i][(this.cols[n])]);
        }
        data[data.length] = row;
      }
      return data;
    }
  };
}
