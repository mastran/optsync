import os, re
import subprocess
import itertools
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate configuration file for a batch of replicas')
    parser.add_argument('--prefix', type=str, default='hotstuff')
    parser.add_argument('--ips', type=str, default=None)
    parser.add_argument('--pub-ips', type=str, default=None)
    parser.add_argument('--iter', type=int, default=10)
    parser.add_argument('--pport', type=int, default=10000)
    parser.add_argument('--cport', type=int, default=20000)
    parser.add_argument('--keygen', type=str, default='./bls-keygen')
    parser.add_argument('--nodes', type=str, default='nodes.txt')
    parser.add_argument('--block-size', type=int, default=1)
    parser.add_argument('--pace-maker', type=str, default='dummy')
    parser.add_argument('--output', type=str, default='')

    args = parser.parse_args()

    if args.ips is None:
        ips = ['127.0.0.1']
    else:
        ips = [l.strip() for l in open(args.ips, 'r').readlines()]

    if args.pub_ips is None:
        pub_ips = ips
    else:
        pub_ips = [l.strip() for l in open(args.pub_ips, 'r').readlines()]

    prefix = args.prefix
    iter = args.iter
    base_pport = args.pport
    base_cport = args.cport
    keygen_bin = args.keygen

    base_path = args.output
    base_path += '/' if base_path and base_path[-1] != '/' else ''

    main_conf = open(base_path + "{}.conf".format(prefix), 'w')
    nodes = open(base_path + args.nodes, 'w')
    replicas = ["{}:{};{}".format(ip, base_pport + i, base_cport + i)
                for ip in ips
                for i in range(iter)]
    rep_pub = ["{}:{};{}".format(ip, base_pport + i, base_cport + i)
               for ip in pub_ips
               for i in range(iter)]
    p = subprocess.Popen([keygen_bin, '--num', str(len(replicas))],
                        stdout=subprocess.PIPE, stderr=open(os.devnull, 'w'))

    generator = p.stdout.readline()[3:-1]
    keys = [[p.stdout.readline()[5:-1], p.stdout.readline()[5:-1]] for _ in range(len(replicas))]
    if not (args.block_size is None):
        main_conf.write("block-size = {}\n".format(args.block_size))
    if not (args.pace_maker is None):
        main_conf.write("pace-maker = {}\n".format(args.pace_maker))
    main_conf.write("generator = {}\n".format(generator))
    for r in zip(replicas, keys, itertools.count(0)):
        main_conf.write("replica = {}- {}\n".format(r[0], r[1][0]))
        r_conf_name = "{}-sec{}.conf".format(prefix, r[2])
        nodes.write("{}:{}\t{}\n".format(r[2], rep_pub[r[2]], r_conf_name))
        r_conf = open(base_path + r_conf_name, 'w')
        r_conf.write("privkey = {}\n".format(r[1][1]))
        r_conf.write("idx = {}\n".format(r[2]))
