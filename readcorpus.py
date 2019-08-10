#!/usr/bin/python3

# CS 373 - Homework 4
# Caleb Schmidt
# schmical@oregonstate.edu
# 8/9/2019

import sys
import json
import math
import getopt


def usage():
    '''
    Prints a usage message to stdout.
    '''
    print("Usage: %s --file=[filename]" % sys.argv[0])
    sys.exit()


def main():
    '''
    Parses command line args and delegates
    classification of the specified file.
    '''
    file = ''
    myopts, args = getopt.getopt(sys.argv[1:], "", ["file="])

    # Get passed filename
    for opt, arg in myopts:
        if opt in ('-f', '--file'):
            file = arg
        else:
            usage()

    if not len(file):
        usage()

    # Read in the specified file
    with open(file, encoding='latin1') as f:
        urldata = json.load(f)

    # Delegate to classification function
    classify_urls(urldata)


def classify_urls(urldata, threshold=3):
    '''
    Takes URL data and a score threshold and
    then aggregates weighted scores from various
    scoring functions to create an overall score
    and determine if a URL is malicious or not.
    Writes gross statistics to stdout and individual
    classifications to url_classifications.txt.
    '''
    guess = list()

    for record in urldata:
        # Get each individual score and associate with a weight
        weighted_scores = [
            (calc_fragment_score(record), 3),
            (calc_domain_age_score(record), 3),
            (calc_tld_score(record), 1),
            (calc_ip_score(record), 3),
            (calc_port_score(record), 1),
            (calc_file_extension_score(record), 1)
        ]

        # Calculate the weighted sum of scores
        total_score = sum(score * weight for score, weight in weighted_scores)

        # Flag as malicious if over the threshold
        is_malicious = 1 if total_score >= threshold else 0

        # Save our guess
        guess.append((is_malicious, record['url']))

    # Display overall stats for the classified URLs
    print(f'Malicious: {sum(i for i, url in guess) / len(urldata):.2%}')
    print(f'Safe: {sum(i == 0 for i, url in guess) / len(urldata):.2%}')

    # Save individual classifications to file
    with open('url_classifications.txt', 'wt') as f:
        lines = [','.join([str(url), str(flag)]) for flag, url in guess]
        f.write('\n'.join(lines))


def calc_file_extension_score(record):
    '''
    Essentially, only flag as malicious if
    the file extension is php.
    '''
    if record.get('file_extension', '') == 'php':
        return 1
    return 0


def calc_alexa_score(record):
    '''
    If a URL has an Alexa rank, return the log 10
    divided by 6, roughly scaling to 0-1 for all
    possible rankings, with lower scores resulting in
    a lower possibility of maliciousness.
    '''
    rank = record.get('alexa_rank')
    if rank:
        return math.log10(int(rank)) / 6
    return 1


def calc_port_score(record):
    '''
    Flag a URL as potentially malicious if it
    is not using ports 80 or 443.
    '''
    port = record.get('default_port', -1)
    if port not in [80, 443]:
        return 1
    return 0


def calc_ip_score(record):
    '''
    Flag URLs with no associated IPs as
    potentially malicious.
    '''
    ips = record.get('ips', [])
    if not ips:
        return 1
    return 0


def calc_tld_score(record):
    '''
    If a TLD is not one of a select handful,
    flag it as potentially malicious.
    '''
    tld = record.get('tld', '')
    if tld in 'com org mil edu gov'.split():
        return 0
    return 1


def calc_domain_age_score(record):
    '''
    If the domain is less than one year old,
    flag it as potentially malicious.
    '''
    days = int(record.get('domain_age_days', '0'))
    if days < 365:
        return 1
    return 0


def calc_fragment_score(record):
    '''
    If a URL has a fragment, flag it as
    potentially malicious.
    '''
    frag = record.get('fragment')
    if frag:
        return 1
    return 0


if __name__ == "__main__":
    main()
