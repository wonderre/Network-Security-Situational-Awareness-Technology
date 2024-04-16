import csv
import pandas as pd
import numpy as np
from fractions import Fraction
import os
#攻击频率
def N_freq(x):
    re=[0,0,0,0,0]
    if x>=0 and x<0.2:
        re[0]=1
    else:
        f=-1.25*x+1.25
        re[0]=round(f,2)

    if x>=0 and x<0.2:
        f=x+0.8
        re[1]=round(f,2)
    elif x>=0.2 and x<0.4:
        re[1]=1
    else:
        f=-(5/3)*x+5/3
        re[1]=round(f,2)

    if x>=0 and x<0.4:
        f=x+0.6
        re[2]=round(f,2)
    elif x>=0.4 and x<0.6:
        re[2]=1
    else:
        f=-2.5*x+2.5
        re[2]=round(f,2)

    if x>=0 and x<0.6:
        f=x+0.4
        re[3]=round(f,2)
    elif x>=0.6 and x<0.8:
        re[3]=1
    else:
        f=-5*x+5
        re[3]=round(f)

    if x>=0 and x<0.8:
        f=1.25*x
        re[4]=round(f,2)
    else:
        re[4]=1
    return re

#攻击种类
def N_type(x):
    re=[0,0,0,0,0]
    if x==0:
        re=[1,0.6,0.4,0.2,0]
    elif x==1:
        re=[0,1,0.6,0.4,0]
    elif x==2:
        re=[0,0,1,0.6,0.4]
    elif x==3:
        re=[0,0,0,1,0.6]
    else:
        re=[0,0,0,0,1]
    return re
#TCP协议数据包占比
def TCP_ratio(x):
    re=[0,0,0,0,0]
    if x>=0 and x<0.7:
        re[0]=1
    else:
        f=-(10/3)*x+10/3
        re[0]=round(f,2)

    if x<0.7:
        f=(10/7)*x
        re[1]=round(f,2)
    elif x>=0.7 and x<0.75:
        re[1]=1
    else:
        f=-4*x+4
        re[1]=round(f,2)

    if x<0.75:
        f=(4/3)*x
        re[2]=round(f,2)
    elif x>=0.75 and x<0.8:
        re[2]=1
    else:
        f=-5*x+5
        re[2]=round(f,2)

    if x<0.8:
        f=1.25*x
        re[3]=round(f,2)
    elif x>=0.8 and x<0.9:
        re[3]=1
    else:
        f=-10*x+10
        re[3]=round(f,2)

    if x>=0 and x<0.9:
        f=(10/9)*x
        re[4]=round(f,2)
    else:
        re[4]=1
    return re

#UDP协议数据包占比
def UDP_ratio(x):
    re=[0,0,0,0,0]
    if x>=0 and x<0.3:
        f=(10/3)*x
        re[0]=round(f,2)
    else:
        re[0]=1

    if x>=0 and x<0.25:
        f=x+0.75
        re[1]=round(f,2)
    elif x>=0.25 and x<0.3:
        re[1]=1
    else:
        f=-(10/7)*x+10/7
        re[1]=round(f,2)

    if x>=0 and x<0.2:
        f=x+0.8
        re[2]=round(f,2)
    elif x>=0.2 and x<0.25:
        re[2]=1
    else:
        f=-(4/3)*x+4/3
        re[2]=round(f,2)

    if x>=0 and x<0.1:
        f=x+0.9
        re[3]=round(f,2)
    elif x>=0.1 and x<0.2:
        re[3]=1
    else:
        f=-(5/4)*x+5/4
        re[3]=round(f,2)

    if x>=0 and x<0.1:
        re[4]=1
    else:
        f=-(10/9)*x+10/9
        re[4]=round(f,2)
    return re

#下载上传比率
def Downup_ratio(x):
    re=[0,0,0,0,0]
    if x>=0 and x<0.45:
        f=x+0.55
        re[0]=round(f,2)
    elif x>=0.45 and x<0.55:
        re[0]=1
    elif x>=0.55 and x<=1.55:
        f=-1*x+1.55
        re[0]=round(f,2)

    if x>=0 and x<0.3:
        f=x+0.7
        re[1]=round(f,2)
    elif x>=0.3 and x<0.45:
        re[1]=1
    elif x>=0.45 and x<=1.45:
        re[1]=-1*x+1.45

    if x>=0 and x<0.2:
        f=x+0.8
        re[2]=round(f,2)
    elif x>=0.2 and x<0.3:
        re[2]=1
    elif x>=0.3 and x<=1.8:
        f=-(2/3)*x+1.2
        re[2]=round(f,2)

    if x>=0 and x<0.55:
        f=x+0.45
        re[3]=round(f,2)
    elif  x>=0.55 and x<0.7:
        re[3]=1
    elif x>=0.7 and x<=1.5:
        f=-1.25*x+1.875
        re[3]=round(f,2)

    if (x>=0 and x<0.2) or x>=0.7:
        re[4]=1
    elif x>=0.2 and x<0.5:
        f=-(10/3)*x+5/3
        re[4]=round(f,2)
    elif x>=0.5 and x<0.7:
        f=5*x-2.5
        re[4]=round(f,2)
    return re
#小于32字节的数据包占比
def Pkt_Small(x):
    re=[0,0,0,0,0]
    if x==0:
        re[0]=0.3
    elif x>0 and x<=0.2:
        re[0]=1
    elif x>0.2 and x<=0.6:
        re[0]=-2.5*x+1.5
        re[0]=round(re[0],2)
    else:
        re[0]=0.1

    if x==0:
        re[1]=0
    elif x>0 and x<=0.2:
        f=0.8
        re[1]=round(re[1],2)
    elif x>0.2 and x<=0.4:
        re[1]=1
    elif x>0.4 and x<=0.6:
        re[1]=-4*x+2.6
        re[1]=round(re[1],2)
    else:
        re[1]=0.2

    if x==0:
        re[2]=0.5
    elif x>0 and x<=0.6:
        re[2]=(5/3)*x
    elif x > 0.6 and x <= 1:
        re[2] = 1
        re[2]=round(re[2],2)

    if x==0:
        re[3]=0.8
    elif x>0 and x<=0.4:
        re[3]=0
    elif x>0.4 and x<=0.6:
        f=1
        re[3]=round(re[3],2)
    else:
        re[3]=0.8
        re[3]=round(re[3],2)

    if x==0:
        re[4]=1
    elif x>0 and x<=0.4:
        re[4]=0
    elif x>0.4 and x<=0.6:
        re[4]=0.8
        re[4]=round(re[4],2)
    else:
        re[4]=-0.5*x+1.1
        re[4] = round(re[4], 2)
    return re

#大于100字节的数据包占比
def Pkt_Big(x):
    re=[0,0,0,0,0]
    if x>=0 and x<=0.2:
        re[0]=0
    elif x>0.2 and x<=0.3:
        re[0]=1
    else:
        f=-(10/3)*x+10/3
        re[0]=round(f,2)

    if x==0:
        re[1]=0.2
    elif x>0 and x<=0.3:
        f=(10/3)*x
        re[1]=round(f,2)
    elif x>0.3 and x<=0.4:
        re[1]=1
    elif x>0.4 and x<=0.9:
        f=-2*x+1.8
        re[1]=round(f,2)
    else:
        f=2*x-2

    if x==0:
        re[2]=0.4
    elif x>0 and x<=0.4:
        re[2]=0
    elif x>0.4 and x<=0.9:
        f=(10/7)*x-9/7
        re[2]=round(f,2)
    else:
        re[2]=1

    if x==0:
        re[3]=0.6
    elif x>0 and x<=0.4:
        re[3]=0
    elif x>0.4 and x<=0.6:
        re[3]=1
    else:
        f=2.23*x+2.15
        re[3]=round(f,2)

    if x==0:
        re[4]=0.7
    elif x>0 and x<=0.4:
        re[4]=0
    elif x>0.4 and x<=0.6:
        f=5*x-2
        re[4]=round(f,2)
    elif x>0.6 and x<=0.8:
        re[4]=1
    else:
        f=-5*x+5
        re[4]=round(f,2)
    return re

def Flow_Dur(x):
    y = [0,0,0,0,0]
    if x>=0 and x<=40000:
        y[0] = 0.2
        y[1] = 0.3
        y[2] = 0.4
        y[3] = 0.8
        y[4] = 0.9
    elif x>40000 and x<=2000000:
        y[0] = 0.1
        y[1] = 0.2
        y[2] = 0.2
        y[3] = 0.4
        y[4] = 0.3
    elif x>2000000 and x<=200000000:
        y[0] = 0.8
        y[1] = 0.7
        y[2] = 0.6
        y[3] = 0.3
        y[4] = 0.2
    return y

def Pkt_Len_Std(x):
    y = [0, 0, 0, 0, 0]
    x = x/100
    if x>=0 and x<1:
        y[0] = 0.1
    elif x>=1 and x<2:
        y[0] = 1
    elif x >= 2 and x < 3:
        y[0] = -0.6*x+1.2
    elif x >= 3 and x < 4:
        y[0] = 0.2 * x-2
    elif x >= 4:
        y[0] = 0
    if x >= 0 and x < 1:
        y[1] = 0.2
    elif x >= 1 and x < 3:
        y[1] = 0.4*x-0.2
    elif x >= 3 and x < 4:
        y[1] = 1
    elif x >= 4:
        y[1] = 0
    if x >= 0 and x < 1:
        y[2] = 0.3
    elif x >= 1 and x < 2:
        y[2] = 0.7*x-0.4
    elif x >= 2 and x < 3:
        y[2] = 1
    elif x >= 3 and x < 4:
        y[2] = -0.6 * x + 2.8
    elif x >= 4:
        y[2] = 0

    if x == 0:
        y[3] = 0.8
    elif x>0 and x<=1:
        y[3] = 1
    elif x > 1 and x <= 4:
        y[3] = -Fraction(2,30)+Fraction(32,30)
    elif x>4:
        y[3] = 0.8

    if x>=0 and x<1:
        y[4] = -0.2*x+1
    elif x>=1 and x<3:
        y[4] = 0.1*x
    elif x >= 3 and x < 4:
        y[4] = -0.1*x+0.6
    elif x >= 4:
        y[4] = 0.2
    format(float(y[0]) , '.2f')
    format(float(y[1]) , '.2f')
    format(float(y[2]) , '.2f')
    format(float(y[3]) , '.2f')
    format(float(y[4]) , '.2f')
    return y

if __name__=="__main__":
    df=pd.read_excel(r"C:\Users\xiqian\Desktop\基于模糊综合评价的网络安全态势感知技术\index\index.xlsx","Sheet1")
    cols=["N_type","N_freq","Total_TCP","Total_UDP","T_ratio_Small","T_ratio_Big","T_DownUp_Ratio",\
          "T_PktLen","T_Flowdur"]
    y=df.shape[0]
    print(y)
    count = 1
    for i in range(y):
        mark=[]
        data=df.loc[i,cols]
        mark.append(N_type(data.iloc[0]))
        mark.append(N_freq(data.iloc[1]))
        mark.append(TCP_ratio(data.iloc[2]))
        mark.append(UDP_ratio(data.iloc[3]))
        mark.append(Pkt_Small(data.iloc[4]))
        mark.append(Pkt_Big(data.iloc[5]))
        mark.append(Downup_ratio(data.iloc[6]))
        mark.append(Pkt_Len_Std(data.iloc[7]))
        mark.append(Flow_Dur(data.iloc[8]))
        output_dir = os.getcwd() + "\\Mark"
        if not os.path.exists(output_dir):
            os.mkdir(output_dir)
        f = open(output_dir+r"\mark"+str(count)+".csv",'w',newline='')
        writer = csv.writer(f)
        for j in mark:
            writer.writerow(j)
        f.close()
        count += 1

