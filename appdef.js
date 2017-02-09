app = function() {
	var isPassthru = function(r, c) {
		passthru = /^passthru/.test(r.URL.RawQuery);
		
		c.Log.WithFields({"Tag":"polysploit-dind","Event":"appdef.IsRequestPassthru."+passthru,"Path":r.URL.Path,"QueryString":r.URL.RawQuery}).Infof("isPassthru(): %s", passthru);
		
		return passthru;
	};

	var isPathAllowed = function(r, c) {
		allowed = (
			(r.URL.Path == "/") ||
			(r.URL.Path == "/health") ||
			(r.URL.Path == "/event") ||
			(r.URL.Path == "/infect") ||
			(r.URL.Path == "/reflect") ||
			(r.URL.Path == "/proxy") ||
			(r.URL.Path == "/docker") ||
			(r.URL.Path == "/panic") ||
			/^\/api\/v0\//.test(r.URL.Path)
    		);

		c.Log.WithFields({"Tag":"polysploit-dind","Event":"appdef.IsRequestedSupported."+allowed,"Path":r.URL.Path,"QueryString":r.URL.RawQuery}).Infof("isPathAllowed(): %s", allowed);
		return allowed;
	};

	return {
		Name: function() {
			return "polysploit";
		},
		IsRequestSupported: function(r, c) {
			if (isPassthru(r, c)) {
				return true;
			}

			return isPathAllowed(r,c);
		},
		Route: function(r, c) {
			c.Log.WithFields({"Tag":"polysploit-dind"}).Infof("[APPDEF] in Route() Request: %v", r);

//			if ((r.Method === "POST") && (r.Form["ID"] === undefined)) {
//				c.Log.WithFields({"Tag":"polysploit-dind"}).Infof("returning null: r.Method = %s, r.Form[\"ID\"] = %s", r.Method, r.Form["ID"]); 
//				return null;
//			}		

			var id = ((r.Method === "POST") && (r.Form["ID"] != undefined) && (r.Form["ID"][0] != undefined)) ? r.Form["ID"][0] : "default";

			var baseImage = ((r.Method === "POST") && (r.Form["BaseImage"] != undefined) && (r.Form["BaseImage"][0] != undefined)) ? r.Form["BaseImage"][0] : "polyverse/polysploit:13e8772fab4604de80ce641668cc8208b58a0438";
			
			var healthCheckURLPath = ((r.Method === "POST") && (r.Form["HealthCheckURLPath"] != undefined) && (r.Form["HealthCheckURLPath"][0] != undefined)) ? r.Form["HealthCheckURLPath"][0] : "/";

			var perInstanceTimeout = ((r.Method === "POST") && (r.Form["PerInstanceTimeout"] != undefined) && (r.Form["PerInstanceTimeout"][0] != undefined)) ? Number(r.Form["PerInstanceTimeout"][0]) : 10000000000;

			var desiredInstances = ((r.Method === "POST") && (r.Form["DesiredInstances"] != undefined) && (r.Form["DesiredInstances"][0] != undefined)) ? Number(r.Form["DesiredInstances"][0]) : 3;

			var isStateless = ((r.Method === "POST") && (r.Form["IsStateless"] != undefined) && (r.Form["IsStateless"][0] != undefined)) ? /^true$/i.test(r.Form["IsStateless"][0]) : true;
			
			var bindingPort = ((r.Method === "POST") && (r.Form["BindingPort"] != undefined) && (r.Form["BindingPort"][0] != undefined)) ? Number(r.Form["BindingPort"][0]) : 8080;

			c.Log.WithFields({"Tag":"polysploit-dind"}).Infof("[APPDEF] Method = %v, ID = %s, BaseImage = %s, PerInstanceTimeout = %v, DesiredInstances = %v, IsStateless = %v, HealthCheckURLPath = %s, BindingPort = %v", r.Method, id, baseImage, perInstanceTimeout, desiredInstances, isStateless, healthCheckURLPath, bindingPort);

			return {
				ID: id,
				Timeout: 365 * 24 * 60 * 60 * 1000000000,
				BackendSSL: false,
				SSLSkipCertVerify: true,
				ContainerChain: {
					IsStateless: isStateless,
					PerInstanceTimeout: perInstanceTimeout,
					DesiredInstances: desiredInstances,
					ConnectionDrainGracePeriod: 3 * 1000000000,
					Chain: [
						{
							BaseImage: baseImage,
							HealthCheckURLPath: healthCheckURLPath,
							LaunchGracePeriod: 60 * 1000000000,
							Cmd: [],
							Env: [],
							BindingPort: bindingPort
						}
					]
				}
			};
		},
		ValidationInfo: function() {
			return {
				PositiveRequests: [],
				NegativeRequests: []
			}
		}
	};
}();
