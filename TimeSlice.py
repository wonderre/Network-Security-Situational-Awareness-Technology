# -*- coding: utf-8 -*-
import pandas as pd
import time
import os
import glob
# 定义 CSV 文件中的列名
cols = ["Timestamp", "Protocol", "Pkt Size Avg", "Down/Up Ratio", "Active Std", \
            "Pkt Len Std", "Label","Flow Duration"]

def slice(file_path,start,end):
    count=-1
    df = pd.read_csv(file_path)  # 读取文件，自动添加行索引和列索引
    df = df.sort_values(by="Timestamp", ascending=True, axis=0, ignore_index=True)
    timeStamp = df.loc[:, "Timestamp"].values  # 获取TimeStamp一列的数据
    timeArray_ini = time.strptime(timeStamp[0], r"%d/%m/%Y %H:%M:%S")
    stamp_ini = time.mktime(timeArray_ini)
    for t in timeStamp:
        count+=1
        timeArray = time.strptime(t, r"%d/%m/%Y %H:%M:%S")
        stamp = time.mktime(timeArray)
        if stamp - stamp_ini > 900:# 如果时间间隔大于 900 秒（15分钟）
            print("在此处切割：", count)
            end.append(count - 1)
            start.append(count)
            timeArray_ini = time.strptime(t, r"%d/%m/%Y %H:%M:%S")
            stamp_ini = time.mktime(timeArray_ini)
    return df,start,end
# 保存切片后的数据到新的 CSV 文件中
def save(df,file_path,start,end):
    index=0
    output_dir = os.getcwd() + "\\Slice"
    if not os.path.exists(output_dir):
        os.mkdir(output_dir)
    file_name = file_path.split("\\")[-1]
    for i in range(len(start) - 1):
        index += 1;
        # print("i:",i)
        df_cols = df.loc[start[i]:end[i], cols]
        # 将切片后的数据保存到新的 CSV 文件中
        df_cols.to_csv(output_dir + "\\" + file_name + "(" + str(index) + ")" + ".csv", index=False, header=cols)
        print("创建文件：", output_dir + "\\" + file_name + "(" + str(index) + ")" + ".csv")

    if len(start) > len(end):
        index += 1;
        # print("index",index)
        df_cols = df.loc[start[-1]:, cols]
        # 将最后一个时间片的数据保存到新的 CSV 文件中
        df_cols.to_csv(output_dir + "\\" + file_name + "(" + str(index) + ")" + ".csv", index=False, header=cols)
        print("创建文件：", output_dir + "\\" + file_name + "(" + str(index) + ")" + ".csv")
if __name__=="__main__":
    input_dir = r"C:\Users\xiqian\Desktop\大创\cicids2018"
    csv_list = glob.glob(input_dir + r'\*.csv')
    print(csv_list)
    unable_csv = [r"C:\Users\xiqian\Desktop\大创\cicids2018\Friday-16-02-2018_TrafficForML_CICFlowMeter.csv", \
                  r"C:\Users\xiqian\Desktop\大创\cicids2018\Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv", \
                  r"C:\Users\xiqian\Desktop\大创\cicids2018\Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv"]
    for each_csv in csv_list:
        start = [0]  # 标识截取的时间片的开始和结束位置
        end = []
        if each_csv in unable_csv:
            continue;
        else:
            print("******处理文件" + each_csv + "***********")
            df,s,e = slice(each_csv,start,end)
            save(df, each_csv,s,e)