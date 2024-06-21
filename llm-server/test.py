# 假设db是已经配置好的DB对象
from models import Feedback

# 打印Feedback类的属性和描述
for attr in dir(Feedback):
    if not attr.startswith('_'):  # 忽略私有属性
        print(f"{attr}: {getattr(Feedback, attr).__doc__}")