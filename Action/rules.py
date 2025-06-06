import requests,sys,time
from datetime import datetime,timezone,timedelta

def get_text(url):
    with requests.get(url, stream= True) as r:
        if r.status_code == 200:
            with open("./Rules/tmp", "wb") as f:
                for chunk in r.iter_content(chunk_size=4096):
                    if chunk:
                        f.write(chunk)
            time.sleep(0.1)
            with open("./Rules/tmp", "r",encoding='utf-8') as f:
                return f.read().strip()
        else:
            sys.exit(0)

############################################################  
############################################################
REJECT_URL = ('https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-domains.txt',
             'https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt')
PROXY_URL = (('https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Proxy/Proxy_Domain.txt',
             'https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/gfw.txt'),
             ('https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Proxy/Proxy.list',
             'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/AppleTV/AppleTV.list',
             'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Netflix/Netflix.list',
             'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/GitHub/GitHub.list',
             'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Google/Google.list',
             'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/YouTube/YouTube.list',
             'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Telegram/Telegram.list',
             'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/TikTok/TikTok.list',
             'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Twitter/Twitter.list',
             'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Facebook/Facebook.list',
             'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Discord/Discord.list',
             'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Instagram/Instagram.list',
             'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/GitLab/GitLab.list',
             'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Pinterest/Pinterest.list',
             'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/OpenAI/OpenAI.list')
            )
DIRECT_URL = ('https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/JingDong/JingDong.list',
              'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/AliPay/AliPay.list',
              'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/WeChat/WeChat.list',
              'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/DouYin/DouYin.list',
              'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/ByteDance/ByteDance.list'
             )

reject_set = set([i for i in get_text(REJECT_URL[0]).split("\n") if not ((len(i) == 0) or i.startswith('#') or i.startswith('!') or i.endswith('.'))])
reject_set.update([i[2:-1] for i in get_text(REJECT_URL[1]).split("\n") if (i.startswith('||') and i.endswith('^') and ( not ('*' in i)) and (not i.endswith('.^')))])
LEN_reject = len(reject_set)
reject_text = '\n'.join(sorted(reject_set))
with open("./Rules/reject.txt", "w",encoding='utf-8') as f:
    f.write(reject_text)
del reject_set,reject_text

proxy_set = set()
for item in PROXY_URL[0]:
    proxy_set.update([i for i in get_text(item).split("\n") if not ((len(i) == 0) or i.startswith('#') or i.startswith('!'))])
LEN_proxy_domain = len(proxy_set)
proxy_text = '\n'.join(sorted(proxy_set))
with open("./Rules/proxy.txt", "w",encoding='utf-8') as f:
    f.write(proxy_text)

proxy_set.clear()
for item in PROXY_URL[1]:
    proxy_set.update([i for i in get_text(item).split("\n") if not ((len(i) == 0) or i.startswith('#') or i.startswith('!'))])
LEN_proxy = len(proxy_set)
proxy_text = '\n'.join(sorted(proxy_set))
with open("./Rules/proxy.list", "w",encoding='utf-8') as f:
    f.write(proxy_text)
del proxy_set,proxy_text

direct_set = set()
for item in DIRECT_URL:
    direct_set.update([i for i in get_text(item).split("\n") if not ((len(i) == 0) or i.startswith('#') or i.startswith('!'))])
LEN_direct = len(direct_set)
direct_text = '\n'.join(sorted(direct_set))
with open("./Rules/direct.list", "w",encoding='utf-8') as f:
    f.write(direct_text)
del direct_set,direct_text

my_stat = []
with open("./Rules/stat", "r",encoding='utf-8') as f:
    my_stat.extend([i[i.rindex(' ')+1:] for i in f.read().strip().split("\n") if not i.startswith('#')])
LEN_reject0,LEN_proxy_domain0,LEN_proxy0,LEN_direct0,LEN_total= int(my_stat[0]),int(my_stat[1]),int(my_stat[2]),int(my_stat[3]),int(my_stat[4])
STR_stat = f'#{(datetime.now().astimezone(timezone(timedelta(hours=8)))).strftime("%Y/%m/%d %H:%M:%S")}(UTC/GMT+08:00)\n\
reject rules({LEN_reject0}{"+" if LEN_reject-LEN_reject0 >= 0 else "-"}{abs(LEN_reject-LEN_reject0)}): {LEN_reject}\n\
proxy-domain rules({LEN_proxy_domain0}{"+" if LEN_proxy_domain-LEN_proxy_domain0 >= 0 else "-"}{abs(LEN_proxy_domain-LEN_proxy_domain0)}): {LEN_proxy_domain}\n\
proxy rules({LEN_proxy0}{"+" if LEN_proxy-LEN_proxy0 >= 0 else "-"}{abs(LEN_proxy-LEN_proxy0)}): {LEN_proxy}\n\
direct rules({LEN_direct0}{"+" if LEN_direct-LEN_direct0 >= 0 else "-"}{abs(LEN_direct-LEN_direct0)}): {LEN_direct}\n\
total rules({LEN_total}{"+" if LEN_reject+LEN_proxy_domain+LEN_proxy+LEN_direct-LEN_total >= 0 else "-"}{abs(LEN_reject+LEN_proxy_domain+LEN_proxy+LEN_direct-LEN_total)}): {LEN_reject+LEN_proxy_domain+LEN_proxy+LEN_direct}'
with open("./Rules/stat", "w",encoding='utf-8') as f:
    f.write(STR_stat)
del my_stat,STR_stat,LEN_reject,LEN_proxy_domain,LEN_proxy,LEN_direct,LEN_reject0,LEN_proxy_domain0,LEN_proxy0,LEN_direct0,LEN_total
