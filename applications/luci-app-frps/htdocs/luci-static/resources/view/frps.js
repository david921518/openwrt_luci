'use strict';
'require view';
'require form';
'require rpc';
'require tools.widgets as widgets';

//	[Widget, Option, Title, Description, {Param: 'Value'}],
var startupConf = [
	[form.Flag, 'stdout', _('Log stdout')],
	[form.Flag, 'stderr', _('Log stderr')],
	[widgets.UserSelect, 'user', _('Run daemon as user')],
	[widgets.GroupSelect, 'group', _('Run daemon as group')],
	[form.Flag, 'respawn', _('Respawn when crashed')],
	[form.DynamicList, 'env', _('Environment variable'), _('OS environments pass to frp for config file template, see <a href="https://github.com/fatedier/frp#configuration-file-template">frp README</a>'), {placeholder: 'ENV_NAME=value'}],
	[form.DynamicList, 'conf_inc', _('Additional configs'), _('Config files include in temporary config file'), {placeholder: '/etc/frp/frps.d/frps_full_example.toml'}]
];

var commonConf = [
	[form.Value, 'bind_addr', _('Bind address'), _('BindAddr specifies the address that the server binds to.<br />By default, this value is "0.0.0.0".'), {datatype: 'ipaddr'}],
	[form.Value, 'bind_port', _('Bind port'), _('BindPort specifies the port that the server listens on.<br />By default, this value is 7000.'), {datatype: 'port'}],
	[form.Value, 'bind_udp_port', _('UDP bind port'), _('BindUdpPort specifies the UDP port that the server listens on. If this value is 0, the server will not listen for UDP connections.<br />By default, this value is 0'), {datatype: 'port'}],
	[form.Value, 'kcp_bind_port', _('KCP bind port'), _('BindKcpPort specifies the KCP port that the server listens on. If this value is 0, the server will not listen for KCP connections.<br />By default, this value is 0.'), {datatype: 'port'}],
	[form.Value, 'proxy_bind_addr', _('Proxy bind address'), _('ProxyBindAddr specifies the address that the proxy binds to. This value may be the same as BindAddr.<br />By default, this value is "0.0.0.0".'), {datatype: 'ipaddr'}],
	[form.Value, 'vhost_http_port', _('Vhost HTTP port'), _('VhostHttpPort specifies the port that the server listens for HTTP Vhost requests. If this value is 0, the server will not listen for HTTP requests.<br />By default, this value is 0.'), {datatype: 'port'}],
	[form.Value, 'vhost_https_port', _('Vhost HTTPS port'), _('VhostHttpsPort specifies the port that the server listens for HTTPS Vhost requests. If this value is 0, the server will not listen for HTTPS requests.<br />By default, this value is 0.'), {datatype: 'port'}],
	[form.Value, 'vhost_http_timeout', _('Vhost HTTP timeout'), _('VhostHttpTimeout specifies the response header timeout for the Vhost HTTP server, in seconds.<br />By default, this value is 60.'), {datatype: 'uinteger'}],
	[form.Value, 'dashboard_addr', _('Dashboard address'), _('DashboardAddr specifies the address that the dashboard binds to.<br />By default, this value is "0.0.0.0".'), {datatype: 'ipaddr'}],
	[form.Value, 'dashboard_port', _('Dashboard port'), _('DashboardPort specifies the port that the dashboard listens on. If this value is 0, the dashboard will not be started.<br />By default, this value is 0.'), {datatype: 'port'}],
	[form.Value, 'dashboard_user', _('Dashboard user'), _('DashboardUser specifies the username that the dashboard will use for login.<br />By default, this value is "admin".')],
	[form.Value, 'dashboard_pwd', _('Dashboard password'), _('DashboardPwd specifies the password that the dashboard will use for login.<br />By default, this value is "admin".'), {password: true}],
	[form.Value, 'assets_dir', _('Assets dir'), _('AssetsDir specifies the local directory that the dashboard will load resources from. If this value is "", assets will be loaded from the bundled executable using statik.<br />By default, this value is "".')],
	[form.Value, 'log_file', _('Log file'), _('LogFile specifies a file where logs will be written to. This value will only be used if LogWay is set appropriately.<br />By default, this value is "console".')],
	[form.ListValue, 'log_level', _('Log level'), _('LogLevel specifies the minimum log level. Valid values are "trace", "debug", "info", "warn", and "error".<br />By default, this value is "info".'), {values: ['trace', 'debug', 'info', 'warn', 'error']}],
	[form.Value, 'log_max_days', _('Log max days'), _('LogMaxDays specifies the maximum number of days to store log information before deletion. This is only used if LogWay == "file".<br />By default, this value is 0.'), {datatype: 'uinteger'}],
	[form.Flag, 'disable_log_color', _('Disable log color'), _('DisableLogColor disables log colors when LogWay == "console" when set to true.<br />By default, this value is false.'), {datatype: 'bool', default: 'true'}],
	[form.Value, 'token', _('Token'), _('Token specifies the authorization token used to authenticate keys received from clients. Clients must have a matching token to be authorized to use the server.<br />By default, this value is "".')],
	[form.Value, 'subdomain_host', _('Subdomain host'), _('SubDomainHost specifies the domain that will be attached to sub-domains requested by the client when using Vhost proxying. For example, if this value is set to "frps.com" and the client requested the subdomain "test", the resulting URL would be "test.frps.com".<br />By default, this value is "".')],
	[form.Flag, 'tcp_mux', _('TCP mux'), _('TcpMux toggles TCP stream multiplexing. This allows multiple requests from a client to share a single TCP connection.<br />By default, this value is true.'), {datatype: 'bool', default: 'true'}],
	[form.Value, 'custom_404_page', _('Custom 404 page'), _('Custom404Page specifies a path to a custom 404 page to display. If this value is "", a default page will be displayed.<br />By default, this value is "".')],
	[form.Value, 'allow_ports', _('Allow ports'), _('AllowPorts specifies a set of ports that clients are able to proxy to. If the length of this value is 0, all ports are allowed.<br />By default, this value is an empty set.')],
	[form.Value, 'max_ports_per_client', _('Max ports per client'), _('MaxPortsPerClient specifies the maximum number of ports a single client may proxy to. If this value is 0, no limit will be applied.<br />By default, this value is 0.'), {datatype: 'uinteger'}],
	[form.Value, 'heartbeat_timeout', _('Heartbeat timeout'), _('HeartBeatTimeout specifies the maximum time to wait for a heartbeat before terminating the connection. It is not recommended to change this value.<br />By default, this value is 90.'), {datatype: 'uinteger'}],
	[form.DynamicList, '_', _('Additional settings'), _('This list can be used to specify some additional parameters which have not been included in this LuCI.'), {placeholder: 'Key-A=Value-A'}]
];

var mainConf = [
	[form.Value, 'enabled', _('Enable FRP Server'), _('enabled specifies if frps service enabled.<br />By default, this value is "0".'), {datatype: 'uinteger'}],
	[form.Value, 'bindAddr', _('Bind address'), _('bindAddr specifies the address that the server binds to.<br />By default, this value is "0.0.0.0".'), {datatype: 'ipaddr'}],
	[form.Value, 'bindPort', _('Bind port'), _('bindPort specifies the port that the server listens on.<br />By default, this value is 7000.'), {datatype: 'port'}],
	[form.Value, 'kcpBindPort', _('KCP bind port'), _('kcpBindPort specifies the KCP port that the server listens on. If this value is 0, the server will not listen for KCP connections.<br />By default, this value is 0.'), {datatype: 'port'}],
	[form.Value, 'quicBindPort', _('QUIC bind port'), _('quicBindPort specifies the QUIC port that the server listens on. If this value is 0, the server will not listen for QUIC connections.<br />By default, this value is 0.'), {datatype: 'port'}],
	[form.Value, 'proxyBindAddr', _('Proxy bind address'), _('ProxyBindAddr specifies the address that the proxy binds to. This value may be the same as BindAddr.<br />By default, this value is "0.0.0.0".'), {datatype: 'ipaddr'}],
	[form.Value, 'transport__quic__keepalivePeriod', _('QUIC Keepalive Period'), _('transport.quic.keepalivePeriod specifies the keepalive period for the QUIC server, in seconds.<br />By default, this value is 10.'), {datatype: 'uinteger'}],
	[form.Value, 'transport__quic__maxIdleTimeout', _('QUIC Max Idle Timeout'), _('transport.quic.maxIdleTimeout specifies the maximum idle timeout for the QUIC server, in seconds.<br />By default, this value is 30.'), {datatype: 'uinteger'}],
	[form.Value, 'transport__quic__maxIncomingStreams', _('QUIC Max Incoming Streams'), _('transport.quic.maxIncomingStreams specifies the maximum incoming streams for the QUIC server, in bps.<br />By default, this value is 100000.'), {datatype: 'uinteger'}],
	[form.Value, 'transport__heartbeatTimeout', _('Heartbeat timeout'), _('transport.heartbeatTimeout specifies the maximum time to wait for a heartbeat before terminating the connection. It is not recommended to change this value.<br />By default, this value is 90.'), {datatype: 'uinteger'}],
	[form.Value, 'transport__maxPoolCount', _('Max Pool Count'), _('transport.maxPoolCount specifies the maximum pool count in each proxy, which will keep no more than maxPoolCount.<br />By default, this value is 5.'), {datatype: 'uinteger'}],
	[form.Flag, 'transport__tcpMux', _('TCP mux'), _('transport.tcpMux toggles TCP stream multiplexing. This allows multiple requests from a client to share a single TCP connection.<br />By default, this value is true.'), {datatype: 'bool', default: 'true'}],
	[form.Value, 'transport__tcpMuxKeepaliveInterval', _('TCP mux Keepalive Interval'), _('transport.tcpMuxKeepaliveInterval specifies the keepalive interval for TCP stream multiplexing. It is only valid if tcpMux is true.<br />By default, this value is 30.'), {datatype: 'uinteger'}],
	[form.Value, 'transport__tcpKeepalive', _('TCP Keepalive'), _('transport.tcpKeepalive specifies the interval between keep-alive probes for an active network connection between frpc and frps. If negative, keep-alive probes are disabled.<br />By default, this value is 7200.'), {datatype: 'integer'}],
	[form.Flag, 'transport__tls__force', _('Force TLS-encrypted connection'), _('transport.tls.force specifies whether to only accept TLS-encrypted connections.<br />By default, this value is false.'), {datatype: 'bool', default: 'false'}],
	[form.Value, 'transport__tls__certFile', _('Certificate File used to serve TLS-encrypted connection'), _('transport.tls.certFile specifies certificate file used to serve TLS-encrypted connections.<br />By default, this value is server.crt')],
	[form.Value, 'transport__tls__keyFile', _('Private key File used to serve TLS-encrypted connection'), _('transport.tls.keyFile specifies private key file used to serve TLS-encrypted connections.<br />By default, this value is server.key')],
	[form.Value, 'transport__tls__trustedCaFile', _('Trusted CA File used to serve TLS-encrypted connection'), _('transport.tls.trustedCaFile specifies trusted CA file used to serve TLS-encrypted connections.<br />By default, this value is ca.crt')],
	[form.Value, 'vhostHTTPPort', _('Vhost HTTP port'), _('vhostHTTPPort specifies the port that the server listens for HTTP Vhost requests. If this value is 0, the server will not listen for HTTP requests.<br />By default, this value is 0.'), {datatype: 'port'}],
	[form.Value, 'vhostHTTPSPort', _('Vhost HTTPS port'), _('vhostHTTPSPort specifies the port that the server listens for HTTPS Vhost requests. If this value is 0, the server will not listen for HTTPS requests.<br />By default, this value is 0.'), {datatype: 'port'}],
	[form.Value, 'vhostHTTPTimeout', _('Vhost HTTP timeout'), _('vhostHTTPTimeout specifies the response header timeout for the Vhost HTTP server, in seconds.<br />By default, this value is 60.'), {datatype: 'uinteger'}],
	[form.Value, 'tcpmuxHTTPConnectPort', _('TCP HTTP CONNECT port'), _('tcpmuxHTTPConnectPort specifies the port that the server listens for TCP HTTP CONNECT requests. If this value is 0, the server will not multiplex TCP requests on one single port. If it is not - it will listen on this value for HTTP CONNECT requests.<br />By default, this value is 0.'), {datatype: 'port'}],
	[form.Flag, 'tcpmuxPassthrough', _('Passthrough TCP mux traffic'), _('If tcpmuxPassthrough is true, frps will not do any update on traffic.'), {datatype: 'bool', default: 'false'}],
	[form.Value, 'webServer__addr', _('Dashboard address'), _('webServer.addr specifies the web server address to enable the dashboard for frps.<br /> dashboard is available only if webServer.port is set.'), {datatype: 'ipaddr'}],
	[form.Value, 'webServer__port', _('Dashboard port'), _('webServer.port specifies the port that the dashboard listens on. If this value is 0, the dashboard will not be started.<br />By default, this value is 0.'), {datatype: 'port'}],
	[form.Value, 'webServer__user', _('Dashboard user'), _('DashboardUser specifies the username that the dashboard will use for login.<br />By default, this value is "admin".')],
	[form.Value, 'webServer__password', _('Dashboard password'), _('DashboardPwd specifies the password that the dashboard will use for login.<br />By default, this value is "admin".'), {password: true}],
	[form.Value, 'webServer__tls__certFile', _('Certificate File used to serve Dashboard TLS-encrypted connection'), _('webServer.tls.certFile specifies certificate file used to serve Dashboard TLS-encrypted connections.<br />By default, this value is server.crt')],
	[form.Value, 'webServer__tls__keyFile', _('Private key File used to serve Dashboard TLS-encrypted connection'), _('webServer.tls.keyFile specifies private key file used to serve Dashboard TLS-encrypted connections.<br />By default, this value is server.key')],
	[form.Value, 'webServer__assetsDir', _('Assets dir'), _('webServer.assetsDir specifies the local directory that the dashboard will load resources from. If this value is "", assets will be loaded from the bundled executable using statik.<br />By default, this value is "".')],
	[form.Flag, 'webServer__pprofEnable', _('Enable goland pprof handlers'), _('webServer.pprofEnable specifies if enable golang pprof handlers in dashboard listener.<br />By default, this value is "false".'), {datatype: 'bool'}],
	[form.Flag, 'enablePrometheus', _('Enable prometheus metrics'), _('enablePrometheus will export prometheus metrics on webServer in /metrics api.'), {datatype: 'bool'}],
	[form.Value, 'log__to', _('Log file'), _('log.to specifies console or real logFile path like ./frps.log where logs will be written to.<br />By default, this value is "console".')],
	[form.ListValue, 'log__level', _('Log level'), _('log.level specifies the minimum log level. Valid values are "trace", "debug", "info", "warn", and "error".<br />By default, this value is "info".'), {values: ['trace', 'debug', 'info', 'warn', 'error']}],
	[form.Value, 'log__maxDays', _('Log max days'), _('log.maxDays specifies the maximum number of days to store log information before deletion. This is only used if LogWay == "file".<br />By default, this value is 0.'), {datatype: 'uinteger'}],
	[form.Flag, 'log__disablePrintColor', _('Disable log color'), _('log.disablePrintColor disables log colors when LogWay == "console" when set to true.<br />By default, this value is false.'), {datatype: 'bool', default: 'false'}],
	[form.Flag, 'detailedErrorsToClient', _('Send specific error to frpc'), _('detailedErrorsToClient defines whether to send the specific error (with debug info) to frpc.<br />By default, this value is true.'), {datatype: 'bool', default: 'true'}],
	[form.Value, 'auth__method', _('Method'), _('auth.method specifies what authorization method to use authenticate frpc with frps. If "token" is specified - token will be read into login message. If "oidc" is specified - OIDC (Open ID Connect) token will be issued using OIDC settings.<br />By default, this value is "token".')],
	[form.Value, 'auth__additionalScopes', _('Additional scopes'), _('auth.additionalScopes specifies additional scopes to include authentication information.<br />Optional values are HeartBeats, NewWorkConns.')],
	[form.Value, 'auth__token', _('Token'), _('auth.token specifies the authorization token used to authenticate keys received from clients. Clients must have a matching token to be authorized to use the server.<br />By default, this value is "".')],
	[form.Value, 'auth__oidc__issuer', _('OIDC Issuer'), _('auth.oidc.issuer specifies the issuer to verify OIDC tokens with.<br />By default, this value is "".')],
	[form.Value, 'auth__oidc__audience', _('OIDC Audience'), _('auth.oidc.audience specifies the audience OIDC tokens should contain when validated.<br />By default, this value is "".')],
	[form.Value, 'auth__oidc__skipExpiryCheck', _('OIDC token expired check'), _('auth.oidc.skipExpiryCheck specifies whether to skip checking if the OIDC token is expired.<br />By default, this value is "false".'), {datatype: 'bool'}],
	[form.Value, 'auth__oidc__skipExpiryCheck', _('OIDC token expired check'), _('auth.oidc.skipExpiryCheck specifies whether to skip checking if the OIDC token is expired.<br />By default, this value is "false".'), {datatype: 'bool'}],
	[form.Value, 'userConnTimeout', _('Maximum time to wait for connection'), _('userConnTimeout specifies the maximum time to wait for a work connection.'), {datatype: 'uinteger'}],
	[form.Value, 'allowPorts', _('Allow ports'), _('allowPorts specifies a set of ports that clients are able to proxy to. If the length of this value is 0, all ports are allowed.<br />By default, this value is an empty set.')],
	[form.Value, 'maxPortsPerClient', _('Max ports per client'), _('MaxPortsPerClient specifies the maximum number of ports a single client may proxy to. If this value is 0, no limit will be applied.<br />By default, this value is 0.'), {datatype: 'uinteger'}],
	[form.Value, 'subDomainHost', _('Subdomain host'), _('subDomainHost specifies the domain that will be attached to sub-domains requested by the client when using Vhost proxying. For example, if this value is set to "frps.com" and the client requested the subdomain "test", the resulting URL would be "test.frps.com".<br />By default, this value is "".')],
	[form.Value, 'custom404Page', _('Custom 404 page'), _('custom404Page specifies a path to a custom 404 page to display. If this value is "", a default page will be displayed.<br />By default, this value is "".')],
	[form.Value, 'udpPacketSize', _('UDP Packet Size'), _('udpPacketSize specifies UDP packet size, unit is byte. If not set, the default value is 1500. This parameter should be same between client and server.<br />By default, this value is 1500.'), {datatype: 'uinteger'}],
	[form.Value, 'natholeAnalysisDataReserveHours', _('Retention time for NAT hole'), _('natholeAnalysisDataReserveHours specifies retention time for NAT hole punching strategy data.'), {datatype: 'uinteger'}],
	[form.Value, 'sshTunnelGateway__bindPort', _('SSH Tunnel bind port'), _('sshTunnelGateway.bindPort specifies SSH Tunnel gateway bind port.'), {datatype: 'port'}],
	[form.Value, 'sshTunnelGateway__privateKeyFile', _('SSH Tunnel private key file'), _('sshTunnelGateway.privateKeyFile specifies SSH Tunnel gateway private key file.')],
	[form.Value, 'sshTunnelGateway__autoGenPrivateKeyPath', _('SSH Tunnel auto generate private key path'), _('sshTunnelGateway.autoGenPrivateKeyPath specifies SSH Tunnel gateway auto generate private key path.')],
	[form.Value, 'sshTunnelGateway__authorizedKeysFile', _('SSH Tunnel authorized keys file'), _('sshTunnelGateway.authorizedKeysFile specifies SSH Tunnel gateway authorized keys file.')],
	[form.DynamicList, '_', _('Additional settings'), _('This list can be used to specify some additional parameters which have not been included in this LuCI.'), {placeholder: 'Key-A=Value-A'}]
];

function setParams(o, params) {
	if (!params) return;
	for (var key in params) {
		var val = params[key];
		if (key === 'values') {
			for (var j = 0; j < val.length; j++) {
				var args = val[j];
				if (!Array.isArray(args))
					args = [args];
				o.value.apply(o, args);
			}
		} else if (key === 'depends') {
			if (!Array.isArray(val))
				val = [val];
			for (var j = 0; j < val.length; j++) {
				var args = val[j];
				if (!Array.isArray(args))
					args = [args];
				o.depends.apply(o, args);
			}
		} else {
			o[key] = params[key];
		}
	}
	if (params['datatype'] === 'bool') {
		o.enabled = 'true';
		o.disabled = 'false';
	}
}

function defTabOpts(s, t, opts, params) {
	for (var i = 0; i < opts.length; i++) {
		var opt = opts[i];
		var o = s.taboption(t, opt[0], opt[1], opt[2], opt[3]);
		setParams(o, opt[4]);
		setParams(o, params);
	}
}

function defOpts(s, opts, params) {
	for (var i = 0; i < opts.length; i++) {
		var opt = opts[i];
		var o = s.option(opt[0], opt[1], opt[2], opt[3]);
		setParams(o, opt[4]);
		setParams(o, params);
	}
}

var callServiceList = rpc.declare({
	object: 'service',
	method: 'list',
	params: ['name'],
	expect: { '': {} }
});

function getServiceStatus() {
	return L.resolveDefault(callServiceList('frps'), {}).then(function (res) {
		var isRunning = false;
		try {
			isRunning = res['frps']['instances']['instance1']['running'];
		} catch (e) { }
		return isRunning;
	});
}

function renderStatus(isRunning) {
	var renderHTML = "";
	var spanTemp = '<em><span style="color:%s"><strong>%s %s</strong></span></em>';

	if (isRunning) {
		renderHTML += String.format(spanTemp, 'green', _("frp Server"), _("RUNNING"));
	} else {
		renderHTML += String.format(spanTemp, 'red', _("frp Server"), _("NOT RUNNING"));
	}

	return renderHTML;
}

return view.extend({
	render: function() {
		var m, s, o;

		m = new form.Map('frps', _('frp Server'));

		s = m.section(form.NamedSection, '_status');
		s.anonymous = true;
		s.render = function (section_id) {
			L.Poll.add(function () {
				return L.resolveDefault(getServiceStatus()).then(function(res) {
					var view = document.getElementById("service_status");
					view.innerHTML = renderStatus(res);
				});
			});

			return E('div', { class: 'cbi-map' },
				E('fieldset', { class: 'cbi-section'}, [
					E('p', { id: 'service_status' },
						_('Collecting data ...'))
				])
			);
		}

		s = m.section(form.NamedSection, 'main', 'frps');
		s.dynamic = true;

		s.tab('main', _('Main settings'));
		s.tab('init', _('Startup settings'));

		defTabOpts(s, 'main', mainConf, {optional: true});

		o = s.taboption('init', form.SectionValue, 'init', form.TypedSection, 'init', _('Startup settings'));
		s = o.subsection;
		s.anonymous = true;
		s.dynamic = true;

		defOpts(s, startupConf);

		return m.render();
	}
});
