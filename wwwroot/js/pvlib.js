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
