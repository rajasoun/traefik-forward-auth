package tfa

import (
	"net/http"
	"strings"
	"testing"

	"github.com/gorilla/securecookie"
)

var (
	cookieHashKey     string
	cookieBlockKey    string
	userInfoCookie    string
	largeUserInfo2000 string
	largeUserInfo2500 string
	req               *http.Request
)

func setupTest(t *testing.T) func(t *testing.T) {
	cookieHashKey = "AMC7VVW06NF6NG1BN8WGQR4GGSHYHMKN"
	cookieBlockKey = "R78IRDN6920MJPE2RD7MFQ9Y2GN5AKTJ"
	userInfoCookie = "_user_info"
	largeUserInfo2000 = `yqgdfodb48nzfejz4tyt1n62dazcgi6c2ro5vlnsvo2u7jke44ime9hq9iq0nxybzvd6kvfmm43vurdssvyu52sfm0bapb4jzecjlcpglz4thbq6eogpb1nythbp61gvkwx0iodqoy2wpk36k39x7s54rhnhvslnwfsov1tbziqgnzwubgt9x0uh2mufy09swmor1hhckh791b12y7f5bocpk8285bru3ut4l194cg5gduxym0r2a3lr5zyzm0ram8tqr7rw5bwhzkljgygm0xi1d22tk9srim4u8mwwjh5yh5j0yd7lrf9zcmn9s3gpjrf82ahrxkqcsyzh9lanc6au101p6wvkzh7thf3eom1ekeqj71tpd7iyuqfksytjnobag9tsbsqy87321jv9lwiqkm1mggeb8frzd1220wrsxre2jgbh3f4cdbb9tpnhqy8c3179qpkw82my07qetjvg9dqcrqqz88bzzjvecbxsdlkqneyaqfns1f5kaj1mj3enx1o8oydp4f5adacgqd8upf6y2d7wo8vclzial2dseijlk8puyks7lul4vb2bd7rzd23fj1t3jj3d1j4c5tf2lka370h5o1vnv80t8hgkzwibd10rj05buebkapkterweltat0u82az56pre2r7wyhimrl302r61x5eekna9uyybqxrvzgn180r5c7kupl74o83ugxn5tknis0xkad9thceolh8r1d228pqzah3tsiayaago47yc5tur8l1yiicjr8vlc6u31ir5017dhl1r53bwxsb9p3vpiva1ehlp2z8c8ojxevfr2xroqgfx1pisq7enuper7yqdniwrejkhoqzgbivw4fnwv7olrfjxz6wwyogu3n52o7he4yfyaafwwfszbukabw0x6v4igse08rlnjsdgteyjha8767q8vfq800eop2g703125t4nhxpqkidyph2iuwclxri7qhkgs8ducxlksvxj27ibjmq7u9ty9j8sjv5sydotpi1f7idrarg5nfjhru4r6987qjwdf7g5n7r8gh6h9iedvk1s3f5npa24xztmwj0p2mkopcuwjlybhh7yonswem218gd93hpz8fc41vsnnjyemlcwjdmcf4bmbfgdjzi43w9gubdsr93suq9dledeajybd2s4wjicpyc8uu7pygmqgkoywkju60mpxc2lyoy6neuoitqrmcu10sdmp65dp14k8i1uynay6r9yycnb3nkcyvxlz4os3c4dtg2xqbqxjuc3dwjuf4u5rubjxdmhmwt77ta9rdknhnw1l9yc5b6g4smzeybfav17myhyc2y7rtppkb878h3dz3k2a4o8zndvxf78s0srml87suxry4t6lzssquihw6j2ak0cjb996p3onn1bek080y4oo7xph0qw1379mibxwdq5vjgv5qxdj9y3hjsa7myjmjyyb30nvz251xdxr0s8hj66q1va7z5fmd3rllhx9oeyf27j4lq4lbrqt0hf3uiigw71iij5h2nsaj1i2xbsqfw8m3uelu8op6ioij6ethz5x0upbux15tu1eaxsh13ozdh93yfq4yn59aokaloyh32lup7oi324upsjhvdisd5j4g9lckh1yrvajd1uemndswft3zw7kp1948gi1lrq4hq1rm0kgme52nh72hllacj431cxu9gtoegegrhlyyoy59dn8kecogd175kk73hw5l98qf8kwerk737qbbb6cb0ma4cmb5h8sx5apo9kk9j7ghd3joiszqk3qbqmk5potfcjaebtyyjs30ngtv6u0op42zrth0qsdh9mohbt9e0taonjn4t3ro1p3vx17vsp6bnenmpd2jsa9au3imqavp514b6ue9sgpfkxy94m4cej2814jq8js8d63ydvph801y78emcne94glho0x0ggpkx5oy73gq6ubtx7u548j2623wikx0iakckzfoxmqiz36vn5w9wjx`
	largeUserInfo2500 = `4y93hjd9pfu91k3jtlhyjo9x3mcpmixlkcr1hycn66pviounbiqbouieu0idbxznkhgbnnxsux0fieyqh03dt2bdznb5q4hbbg52e7supslaljy6gwx5r5pkmfg4xhxrdv0wm1zi571z991t6jc9e7mzv7jzq4rqode2yse0yfbxuf4p963ukx3mw2z3i3dqdo6tgry3u9x8j93iy7hna55jppqaj68wsmsesutqkgle88tvrxmxt2rz7iqwsoh6w4dpwxpm4yxssvu2ga2vclyxk81j3ozf40c0lchjew1lcf7ubohmvj1p39oriduy8h580ydb2sj4uocp4j768joeyn2yewrirhhbaj7ndfepe1mghu8x7wbt246jdddzks1f030ouigjox7iw9z0bfcarryrva41zdok6q1es7lgei06qn1z56d5rolq4ne3fglmh6f75hlh3zcgd4yea1vlmbv3iwxyvnjnocl0n9gp8xhjlo2rph28tfdov17b77nf8bfq4cqfc85zydfewysjzi1hq3i9gpndtdthtrucl7v2owb1pucrcqqixr36i4gohmhp3c8luyck6n9g8t268bzvyy95vhf9gy65njkmiyjiiq0999dnwvyiy5gfgq399t13t5amqwaczjuc0fqqu9xrlyy7u604ldqkyzt6jcp23nu0jrhgv69o1bkknoq4qtdvgh3bl44ekupr0hexezxkfe4db8j1u1qkkuawq7u8ei39al7oyg4goltqse79bd30pensbg08p081vii6p618f8pma8viuzl538jy22znp12nt341dg2qy3jnq8yf4wl72982obxf1w0zywilemsa4u1zd1sqgyv1haeth9ommpbp0pwjz0edvobzhsla3zphxu5hsnyjmpojgun2erk9y209ua65j96eoe1q9p94462ok9y65vkfpa6ko5ccc4m9f8vyw3s3ic6t752gy6ludsn9h2uizc01b0zslo43qlunochvm7kvb4qyltmqkb7uomlkyhhxktmlosidrcbdygwum1l9l5ykx9l89ncpdg5enag5xpw1udu5np0mrmm52ehx0n1f6o1nj8sbzhk78n3bfz6ooeojneedk0i7ryudgko62iqcphtkn23zojoz8hmsuggqupuc6fvarf9uje4xwi8uqvueuwmrqp08q85nnojf1atojkh6gyx21nbo2s8j9v89vg441w1rpgo9pk2rjhmy457cw39twwfbnjrf52mv8wstw6mw1o80xsdrck25dk9480iuk5k0pw89nveq23qsbic9twc808vf0lmoxcyd56pmzbzkxuklktcc9n9dmoqx0ncudcomhdqx7fnotikvs7749rqk0db8q9i1jc9u0iybbos7qyw7tjsjx47bzonieoabd1u1m9d2ywf19ub1tda5di6adpbgaojtumld6j6ez2dtvong368kqhgchk5csg1pq8svf7f14pxdi1m1j0l3cebewtperrciq7csphaofq773odcrri9ymc35kb4t1vjl5y0rymajxa6f9b2egf6rhy4h5dfb8qr1fxkptw8h18qnnt0zsgn1m9l9ow15sdegmctch15fhrct5t3b29xr5e5eqprr51sjng4fc1ak794lz4gepza7tab6r8ua14xh4o47vq3cmtmvrtg0yae5v86n73o4mhzqhva7yivqfhlzdm8rn9m3x0403vjolhhjmyyt1eb4fvrhj3f2ogysrse6y6er1s06hr4mcklj8ub4dh17990opzum5k8xyibrczh84jynvwi0nkvshs5ey6eq3a930zmr9q8jnc7uj0ikx5azbgi2krhykorxo7jrvx5q7h2mwxjifokn2mvawjhui7xlsbl4gcuwub7qfj4icyalbiemd1r47gr49sd3yq6lcuftkotcro1pw49uge8f4cusssz47dpcx9k6zun8ya80njf5ijnoh5g90tbiuvtvcym2z8fc4wg3mc2l98neq05roy3p67my6jmon8mmz824ew5amp4z25hgw3kdf80fputwf0gx6er6jyoh9h4z6ottpzu1jnczytsumhcx1y582ye89k7xgf5sdhtk0w5l4oqbdqkzt8rokuhqknpbfgql3vgkdzqb5065tocq9eb77btyyavmijajvf70dpxnoarwdsch22csqrirc10x9i3mzu0izzbcl0h6fnp91jv3tu7qi8srjpudbl5ufslmi27h3ujzgpqaed8gbckgwxr6wt0v6lsq3xjwabm78y8tdobtaemjel38cwvlvh05l480p4cbsbyq8wimf48ab3wmvku07kd69ramd2g9zkg33o0fy4ak6l52rh4m5cb7gl2wlntghr3p2v97un21dmwuzi0fcqeg6sdozwcg5fpmhp94te6lp246068krowog1moxy45vnr8mwly8kcfqjiaaftkvweso3ukoq793dt`
	req, _ = http.NewRequest("GET", "http://domain.com", nil)
	config = &Config{
		CookieHashKey:  cookieHashKey,
		CookieBlockKey: cookieBlockKey,
		UserInfoCookie: userInfoCookie,
	}
	config.Rules = make(map[string]*Rule)
	return func(t *testing.T) {}
}
func TestMakeUserCookie(t *testing.T) {
	setupTest(t)
	type args struct {
		r        *http.Request
		userInfo string
	}
	tests := []struct {
		name    string
		args    args
		want    *http.Cookie
		wantErr bool
	}{
		{
			name: "test_make_user_cookie_data",
			args: args{r: req, userInfo: "test_user_info"},
			want: &http.Cookie{
				Name:  config.UserInfoCookie,
				Value: "test_user_info",
			},
			wantErr: false,
		},
		{
			name: "large input less than case 4096 bytes",
			args: args{r: req, userInfo: largeUserInfo2000},
			want: &http.Cookie{
				Name:  config.UserInfoCookie,
				Value: largeUserInfo2000,
			},
			wantErr: false,
		},
		{
			name:    "large input more than case 4096 bytes",
			args:    args{r: req, userInfo: largeUserInfo2500},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MakeUserCookie(tt.args.r, tt.args.userInfo)
			if (err != nil) != tt.wantErr {
				t.Errorf("MakeUserCookie() error = %v, wantErr %v", err, tt.wantErr)
				t.Error(err)
				return
			}
			if got != nil && !compareCookie(got, tt.want) {
				t.Errorf("MakeUserCookie() = %v, want %v", got, tt.want)
			}
		})
	}
}

func compareCookie(got, want *http.Cookie) bool {
	var s = securecookie.New([]byte(cookieHashKey), []byte(cookieBlockKey))
	if strings.Compare(got.Name, want.Name) != 0 {
		return false
	}
	value := ""
	if err := s.Decode(userInfoCookie, got.Value, &value); err != nil || !strings.Contains(value, want.Value) {
		return false
	}
	return true
}

func TestValidateCookie(t *testing.T) {
	setupTest(t)
	type args struct {
		r *http.Request
		c *http.Cookie
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "Invalid cookie format",
			args: args{
				r: req,
				c: &http.Cookie{
					Name:  config.UserInfoCookie,
					Value: "xyz",
				},
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "Invalid to decode cookie mac",
			args: args{
				r: req,
				c: &http.Cookie{
					Name:  config.UserInfoCookie,
					Value: "abc|pqr|xyz",
				},
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "Invalid cookie mac",
			args: args{
				r: req,
				c: &http.Cookie{
					Name:  config.UserInfoCookie,
					Value: "YWJj|pqr|xyz",
				},
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "Unable to parse cookie expiry",
			args: args{
				r: req,
				c: &http.Cookie{
					Name:  config.UserInfoCookie,
					Value: "70xxALKQKacEZg7-bn6126WX5UFmt8b5o5BxlKd9uV8=|abc|pqr",
				},
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "Cookie has expired",
			args: args{
				r: req,
				c: &http.Cookie{
					Name:  config.UserInfoCookie,
					Value: "Pv9BtRsXs8tN9qlNsqzO0yfKKGSZBGxFaGoKIPBc4TE=|1606221263|HelloWorld",
				},
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "Cookie valid",
			args: args{
				r: req,
				c: &http.Cookie{
					Name:  config.UserInfoCookie,
					Value: "29AlzD6R3GzzbgivPAt13HvQbtLxh5jA33KCGfEEW3c=|3183023056|HelloWorld",
				},
			},
			want:    "HelloWorld",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateCookie(tt.args.r, tt.args.c)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCookie() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ValidateCookie() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateEmail(t *testing.T) {
	setupTest(t)
	config.MatchWhitelistOrDomain = true
	type args struct {
		email    string
		ruleName string
	}
	tests := []struct {
		name                   string
		args                   args
		want                   bool
		whitelist              CommaSeparatedList
		domains                CommaSeparatedList
		rule                   map[string]*Rule
		matchWhitelistOrDomain bool
	}{
		{
			name: "Override with rule config",
			args: args{
				email:    "abc",
				ruleName: "test",
			},
			whitelist: []string{"abc00", "xyz00"},
			domains:   []string{"domain11", "domain22"},
			rule: map[string]*Rule{"test": {
				Action:    "test_action",
				Rule:      "test_rule",
				Provider:  "test_provider",
				Whitelist: []string{"abc", "xyz"},
				Domains:   []string{"domain1", "domain2"},
			}},
			matchWhitelistOrDomain: true,
			want:                   true,
		},
		{
			name: "Override with rule config, email not in Whitelist",
			args: args{
				email:    "abc_",
				ruleName: "test",
			},
			whitelist: []string{"abc00", "xyz00"},
			domains:   []string{"domain11", "domain22"},
			rule: map[string]*Rule{"test": {
				Action:    "test_action",
				Rule:      "test_rule",
				Provider:  "test_provider",
				Whitelist: []string{"abc", "xyz"},
				Domains:   []string{"domain1", "domain2"},
			}},
			matchWhitelistOrDomain: true,
			want:                   false,
		},
		{
			name: "empty lists",
			args: args{
				email:    "abc",
				ruleName: "test",
			},
			whitelist:              []string{},
			domains:                []string{},
			rule:                   map[string]*Rule{"": {}},
			matchWhitelistOrDomain: true,
			want:                   true,
		},
		{
			name: "matchWhitelistOrDomain false",
			args: args{
				email:    "abc_d",
				ruleName: "test",
			},
			whitelist:              []string{"abc", "xyz"},
			domains:                []string{"domain1", "domain2"},
			rule:                   map[string]*Rule{"": {}},
			matchWhitelistOrDomain: false,
			want:                   false,
		},
		{
			name: "config rule, email in Whitelist",
			args: args{
				email:    "abc",
				ruleName: "test",
			},
			whitelist: []string{"abc", "xyz"},
			domains:   []string{"domain1", "domain2"},
			rule: map[string]*Rule{"test": {
				Action:    "test_action",
				Rule:      "test_rule",
				Provider:  "test_provider",
				Whitelist: []string{"abc", "xyz"},
				Domains:   []string{"domain1", "domain2"},
			}},
			matchWhitelistOrDomain: true,
			want:                   true,
		},
		{
			name: "empty Whitelist",
			args: args{
				email:    "abc@domain1.com",
				ruleName: "test",
			},
			whitelist:              []string{},
			domains:                []string{"domain1.com", "domain2.com"},
			rule:                   map[string]*Rule{"": {}},
			matchWhitelistOrDomain: true,
			want:                   true,
		},
	}
	for _, tt := range tests {
		config.Rules = tt.rule
		config.Whitelist = tt.whitelist
		config.Domains = tt.domains
		config.MatchWhitelistOrDomain = tt.matchWhitelistOrDomain
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidateEmail(tt.args.email, tt.args.ruleName); got != tt.want {
				t.Errorf("ValidateEmail() = %v, want %v", got, tt.want)
			}
		})
	}
}
