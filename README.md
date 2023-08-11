# DEPRECATED
I created this before [Terraform](https://www.terraform.io) existed, sometime back in June 2010 
Today I would suggest to use Terraform instead of my script since I no longer 
maintaint it, is here for historical reason only.

### Note:
- Originally the script was written to be able to setup a AWS infra quick, same setup in multiple regions 
  and able to re-create it fast in case of disaster and delete it is needed
- The readme is stripped down
- Network / prefix sizes and IPV6 sections are kept for reference
- Most Mobile device are using IPv6

these below was never part of the repo, added as a FYI
- Aug 2023, AWS charges for public IP
- Most Mobile device are using IPv6
- [IP issue with EKS] (https://betterprogramming.pub/amazon-eks-is-eating-my-ips-e18ea057e045)
```
kubectl -n kube-system set env daemonset aws-node WARM_IP_TARGET=1
```

#### Prefix sizes
```
 /17  255.255.128.0   128 Cs : ~ 4000 instance / zone
 /18  255.255.192.0    64 Cs : ~ 2000 instance / zone
 /19  255.255.224.0    32 Cs : ~ 1000 instance / zone
 /20  255.255.240.0    16 Cs : ~  500 instance / zone
 /21  255.255.248.0     8 Cs : ~  200 instance / zone
```

#### IPv6
If IPv6 is enabledd, this means the VPC will get a /56 assigned by AWS, it a live public IP space
From here the /56 is devided into 2x /57 : first will be use for the FE-network and the second to the BE-network.
Then the FE-subnets and the BE-subnets gets a /64 from the their respective network /57. The /64 assigment
is due to the AWS requirement that the CDIR size must be a /64.

```
 /56 == 256 x /64 ==  4,722,366,482,869,645,213,696 == IPv6 addresses
 /57 == 128 x /64 ==  2,361,183,241,434,822,606,848 == IPv6 addresses
 /64              ==     18,446,744,073,709,551,616 == IPv6 addresses
