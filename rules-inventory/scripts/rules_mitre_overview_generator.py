import pandas as pd
import yaml
import argparse
import datetime

"""
Usage:
python rules-inventory/scripts/rules_mitre_overview_generator.py --rules_file=rules/falco_rules.yaml
"""

BASE_MITRE_URL_TECHNIQUE="https://attack.mitre.org/techniques/"
BASE_MITRE_URL_TACTIC="https://attack.mitre.org/tactics/"
COLUMNS=['rule', 'desc', 'workload', 'mitre_phase', 'mitre_ttp', 'extra_tags', 'extra_tags_list', 'mitre_phase_list', 'enabled']

def arg_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('--rules_file', help='Path to falco rules yaml file')
    return parser.parse_args()

def rules_to_df(rules_file):
    l = []
    with open(rules_file, 'r') as f:
        items = yaml.safe_load(f)
        for item in items:
            if 'rule' in item and 'tags' in item:
                if len(item['tags']) > 0:
                    item['workload'], item['mitre_phase'], item['mitre_ttp'], item['extra_tags'] = [], [], [], []
                    for i in item['tags']:
                        if i in ['host', 'container']:
                            item['workload'].append(i)
                        elif i.startswith('mitre'):
                            item['mitre_phase'].append(i)
                        elif i.startswith('T'):
                            if i.startswith('TA'):
                                item['mitre_ttp'].append('[{}]({}{})'.format(i, BASE_MITRE_URL_TACTIC, i.replace('.', '/')))
                            else:
                                item['mitre_ttp'].append('[{}]({}{})'.format(i, BASE_MITRE_URL_TECHNIQUE, i.replace('.', '/')))
                        else:
                            item['extra_tags'].append(i) 
                    item['workload'].sort()
                    item['mitre_phase'].sort()
                    item['mitre_ttp'].sort()
                    item['mitre_phase_list'] = item['mitre_phase']
                    item['extra_tags_list'] = item['extra_tags']
                    item['enabled'] = (item['enabled'] if 'enabled' in item else True) 
                    l.append([', '.join(item[x]) if x in ['workload', 'mitre_ttp', 'extra_tags', 'mitre_phase'] else item[x] for x in COLUMNS])
        df = pd.DataFrame.from_records(l, columns=COLUMNS)
    return df.sort_values(by=['workload','rule'], inplace=False)

def print_markdown(df):
    n_rules=len(df)

    print('\n\n\n# Falco Rules - Summary Stats\n\n\n')
    print('\n\n\nThis document is auto-generated. Last Updated: {}.\n\n'.format(datetime.date.today()))
    print('The Falco project ships with {} [default rules](https://github.com/falcosecurity/falco/blob/master/rules/falco_rules.yaml) contributed by the community. The intended outcome of this document is to provide a comprehensive overview of the default rules, provide additional resources and help drive future improvements.\n\n\n'.format(n_rules))

    print('\n\n\nFalco default rules per workload type:\n\n\n')
    df_stats1 = df.groupby('workload').agg(rule_count=('workload', 'count'))
    df_stats1['percentage'] = round(100.0 * df_stats1['rule_count'] / df_stats1['rule_count'].sum(), 2).astype(str) + '%'
    print(df_stats1.to_markdown(index=True))

    print('\n\n\nFalco default rules per [Falco tag](https://falco.org/docs/rules/#tags):\n\n\n')
    df_stats2 = df[['rule', 'extra_tags_list']].explode('extra_tags_list')
    df_stats2.rename(columns={'extra_tags_list':'extra_tag'}, inplace=True)
    df_stats2 = df_stats2.groupby('extra_tag').agg(rule_count=('extra_tag', 'count'))
    df_stats2['percentage'] = round(100.0 * df_stats2['rule_count'] / df_stats2['rule_count'].sum(), 2).astype(str) + '%'
    print(df_stats2.to_markdown(index=True))

    print('\n\n\nFalco default rules per [Mitre Attack](https://attack.mitre.org/) phase:\n\n\n')
    df_stats3 = df[['rule', 'mitre_phase_list']].explode('mitre_phase_list')
    df_stats3.rename(columns={'mitre_phase_list':'mitre_phase'}, inplace=True)
    df_stats3.sort_values(by=['mitre_phase','rule'], inplace=True)
    df_stats3 = df_stats3.groupby("mitre_phase").agg({"rule": lambda x: ['\n'.join(list(x)), len(list(x))]})
    df_stats3['rules'] = df_stats3['rule'].apply(lambda x: x[0])
    df_stats3['percentage'] = df_stats3['rule'].apply(lambda x: round((100.0 * x[1] / n_rules), 2)).astype(str) + '%'
    print(df_stats3.drop('rule', axis=1).to_markdown(index=True))

    print('\n\n\n# Falco Rules - Detailed Overview\n\n\n')
    df_stats4 = df.drop(['extra_tags_list', 'mitre_phase_list'], axis=1)
    df_enabled = df_stats4[(df_stats4['enabled'] == True)].drop(['enabled'], axis=1)
    df_disabled = df_stats4[(df_stats4['enabled'] == False)].drop(['enabled'], axis=1)
    print('\n\n{} Falco rules ({:.2f}% of rules) are enabled by default:\n\n'.format(len(df_enabled), (100.0 * len(df_enabled) / n_rules)))
    print(df_enabled.to_markdown(index=False))
    print('\n\n{} Falco rules ({:.2f}% of rules) are *not* enabled by default:\n\n'.format(len(df_disabled), (100.0 * len(df_disabled) / n_rules)))
    print(df_disabled.to_markdown(index=False))
    
if __name__ == "__main__":
    args_parsed = arg_parser()
    print_markdown(rules_to_df(args_parsed.rules_file))
