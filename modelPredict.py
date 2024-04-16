import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import statsmodels.api as sm
from statsmodels.stats.diagnostic import acorr_ljungbox
from statsmodels.graphics.tsaplots import plot_pacf, plot_acf
from pylab import mpl

# 1.载入数据，将默认索引改为时间索引，绘制时序图
df = pd.read_csv(r'predict.csv', parse_dates=['time'])
df.info()
data = df.copy()
data = data.set_index('time')
plt.plot(data.index, data['eval'].values)
# plt.show()
# 划分训练集和测试集
train = data.loc[:'22/02/2018 09:22:21', :]
test = data.loc['22/02/2018 09:37:22':, :]
# 2.平稳性检验
# 单位根检验-ADF检验
print('ADF检验', sm.tsa.stattools.adfuller(train['eval']))
# 3.白噪声检验
mpl.rcParams["font.sans-serif"] = ["SimHei"]
mpl.rcParams["axes.unicode_minus"] = False  # 设置正常显示字体
acorr_ljungbox(train['eval'], lags=[6, 12], boxpierce=True)
# 4.计算ACF,PACF
# 计算ACF
acf = plot_acf(train['eval'])
plt.title("态势感知的自相关图")
plt.show()
# 计算PACF
pacf = plot_pacf(train['eval'])
plt.title("态势感知的偏自相关图")
plt.show()
# 从ACF结果图上来看，p=7,q=4

model = sm.tsa.arima.ARIMA(train['eval'], order=(4, 0, 6))#这里应该设置一个频率
arima_res = model.fit()
arima_res.summary()
# 5因为看自相关图和偏自相关图有很大的主观性，因此，可以通过AIC或BIC来确定最合适的阶数
trend_evaluate = sm.tsa.arma_order_select_ic(train, ic=['aic', 'bic'], trend='n', max_ar=20, max_ma=5)
print('train AIC', trend_evaluate.aic_min_order)
print('train BIC', trend_evaluate.bic_min_order)
# 6模型预测
predict=arima_res.predict("2018/1/3 0:00:00", "2018/1/3 14:00:00")
plt.plot(test.index, test['eval'])
plt.plot(test.index, predict)
plt.legend(['y_true', 'y_pred'])
plt.show()
print(len(predict))
# 7模型评价
from sklearn.metrics import r2_score, mean_absolute_error
mean_absolute_error(test['eval'], predict)
# 8残差分析
res = test['eval']-predict
residual = list(res)
plt.plot(residual)
np.mean(residual)   # 查看残差的均值是否在0附近
# 9残差正态性检验
import seaborn as sns
from scipy import stats
plt.figure(figsize=(10, 5))
ax = plt.subplot(1, 2, 1)
sns.distplot(residual, fit=stats.norm)
ax = plt.subplot(1, 2, 2)
res = stats.probplot(residual,plot=plt)
plt.show()




