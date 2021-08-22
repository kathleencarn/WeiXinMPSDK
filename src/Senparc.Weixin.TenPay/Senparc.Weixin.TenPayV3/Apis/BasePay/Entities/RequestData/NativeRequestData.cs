﻿#region Apache License Version 2.0
/*----------------------------------------------------------------

Copyright 2021 Jeffrey Su & Suzhou Senparc Network Technology Co.,Ltd.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
except in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the
License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
either express or implied. See the License for the specific language governing permissions
and limitations under the License.

Detail: https://github.com/JeffreySu/WeiXinMPSDK/blob/master/license.md

----------------------------------------------------------------*/
#endregion Apache License Version 2.0

/*----------------------------------------------------------------
    Copyright (C) 2021 Senparc
  
    文件名：NativeRequestData.cs
    文件功能描述：Native下单请求数据实体
    
    
    创建标识：Senparc - 20210814

    修改标识：Senparc - 20210819
    修改描述：完善注释; 加入构造函数
    
----------------------------------------------------------------*/

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Senparc.Weixin.TenPayV3.Entities;

namespace Senparc.Weixin.TenPayV3.Apis.BasePay.Entities
{
    public class NativeRequestData
    {
        /// <summary>
        /// 构造函数
        /// </summary>
        /// <param name="appid">由微信生成的应用ID，全局唯一</param>
        /// <param name="mchid">直连商户的商户号，由微信支付生成并下发</param>
        /// <param name="description">商品描述 示例值：Image形象店-深圳腾大-QQ公仔</param>
        /// <param name="out_trade_no">商户系统内部订单号</param>
        /// <param name="time_expire">订单失效时间 遵循rfc3339标准格式，格式为YYYY-MM-DDTHH:mm:ss+TIMEZONE</param>
        /// <param name="attach">附加数据，在查询API和支付通知中原样返回，可作为自定义参数使用</param>
        /// <param name="notify_url">通知URL 必须为直接可访问的URL，不允许携带查询串，要求必须为https地址</param>
        /// <param name="goods_tag">订单优惠标记 示例值：WXG</param>
        /// <param name="amount">订单金额</param>
        /// <param name="detail">优惠功能</param>
        /// <param name="settle_info">结算信息</param>
        /// <param name="scene_info">支付场景描述</param>
        public NativeRequestData(string appid, string mchid, string description, string out_trade_no, TenpayDateTime time_expire, string attach, string notify_url, string goods_tag, Amount amount, Detail detail, Settle_Info settle_info, Scene_Info scene_info)
        {
            this.appid = appid;
            this.mchid = mchid;
            this.description = description;
            this.out_trade_no = out_trade_no;
            this.time_expire = time_expire.ToString();
            this.attach = attach;
            this.notify_url = notify_url;
            this.goods_tag = goods_tag;
            this.amount = amount;
            this.detail = detail;
            this.settle_info = settle_info;
            this.scene_info = scene_info;
        }

        /// <summary>
        /// 应用ID
        /// 由微信生成的应用ID，全局唯一。请求基础下单接口时请注意APPID的应用属性，例如公众号场景下，需使用应用属性为公众号的APPID
        /// 示例值：wxd678efh567hg6787
        /// </summary>
        public string appid { get; set; }

        /// <summary>
        /// 直连商户号
        /// 直连商户的商户号，由微信支付生成并下发。
        /// 示例值：1230000109
        /// </summary>
        public string mchid { get; set; }

        /// <summary>
        /// 商品描述
        /// 示例值：Image形象店-深圳腾大-QQ公仔
        /// </summary>
        public string description { get; set; }

        /// <summary>
        /// 商户订单号
        /// 商户系统内部订单号，只能是数字、大小写字母_-*且在同一个商户号下唯一
        /// 建议：最短失效时间间隔大于1分钟
        /// 示例值：1217752501201407033233368018
        /// </summary>
        public string out_trade_no { get; set; }

        /// <summary>
        /// 订单失效时间
        /// 遵循rfc3339标准格式，格式为YYYY-MM-DDTHH:mm:ss+TIMEZONE
        /// 示例值：2018-06-08T10:34:56+08:00
        /// </summary>
        public string time_expire { get; set; }

        /// <summary>
        /// 附加数据
        /// 附加数据，在查询API和支付通知中原样返回，可作为自定义参数使用
        /// 示例值：自定义数据
        /// </summary>
        public string attach { get; set; }

        /// <summary>
        /// 通知地址
        /// 通知URL必须为直接可访问的URL，不允许携带查询串，要求必须为https地址。
        /// 示例值：https://www.weixin.qq.com/wxpay/pay.php
        /// </summary>
        public string notify_url { get; set; }

        /// <summary>
        /// 订单优惠标记
        /// 示例值：WXG
        /// </summary>
        public string goods_tag { get; set; }

        /// <summary>
        /// 订单金额
        /// </summary>
        public Amount amount { get; set; }

        /// <summary>
        /// 优惠功能
        /// </summary>
        public Detail detail { get; set; }

        /// <summary>
        /// 结算信息
        /// </summary>
        public Settle_Info settle_info;

        /// <summary>
        /// 场景信息 支付场景描述
        /// </summary>
        public Scene_Info scene_info { get; set; }

        public class Amount
        {
            /// <summary>
            /// 总金额
            /// 订单总金额，单位为分。
            /// 示例值：100 (1元)
            /// </summary>
            public int total { get; set; }

            /// <summary>
            /// 货币类型
            /// CNY：人民币，境内商户号仅支持人民币。
            /// 示例值：CNY
            /// </summary>
            public string currency { get; set; }
        }

        /// <summary>
        /// 优惠功能
        /// </summary>
        public class Detail
        {
            /// <summary>
            /// 商家小票ID
            /// 示例值：微信123
            /// </summary>
            public string invoice_id { get; set; }

            /// <summary>
            /// 单品列表
            /// 条目个数限制：[1，6000]
            /// </summary>
            public Goods_Detail[] goods_detail { get; set; }

            /// <summary>
            /// 订单原价
            /// 1、商户侧一张小票订单可能被分多次支付，订单原价用于记录整张小票的交易金额。
            /// 2、当订单原价与支付金额不相等，则不享受优惠。
            /// 3、该字段主要用于防止同一张小票分多次支付，以享受多次优惠的情况，正常支付订单不必上传此参数。
            /// 示例值：608800
            /// </summary>
            public int cost_price { get; set; }
        }

        /// <summary>
        /// 单品列表信息
        /// </summary>
        public class Goods_Detail
        {
            /// <summary>
            /// 商品名称
            /// 商品的实际名称
            /// 示例值：iPhoneX 256G
            /// </summary>
            public string goods_name { get; set; }

            /// <summary>
            /// 微信侧商品编码
            /// 微信支付定义的统一商品编号（没有可不传）
            /// 示例值：1001
            /// </summary>
            public string wechatpay_goods_id { get; set; }

            /// <summary>
            /// 商品数量
            /// 用户购买的数量
            /// 示例值：1
            /// </summary>
            public int quantity { get; set; }

            /// <summary>
            /// 商户侧商品编码
            /// 由半角的大小写字母、数字、中划线、下划线中的一种或几种组成。
            /// 示例值：1246464644
            /// </summary>
            public string merchant_goods_id { get; set; }

            /// <summary>
            /// 商品单价
            /// 商品单价，单位为分
            /// 示例值：828800 (8288元)
            /// </summary>
            public int unit_price { get; set; }
        }

        /// <summary>
        /// 场景信息
        /// </summary>
        public class Scene_Info
        {
            /// <summary>
            /// 商户门店信息
            /// </summary>
            public Store_Info store_info { get; set; }

            /// <summary>
            /// 商户端设备号
            /// 商户端设备号（门店号或收银设备ID）。
            /// 示例值：013467007045764
            /// </summary>
            public string device_id { get; set; }

            /// <summary>
            /// 用户终端IP
            /// 用户的客户端IP，支持IPv4和IPv6两种格式的IP地址。
            /// 示例值：14.23.150.211
            /// </summary>
            public string payer_client_ip { get; set; }
        }

        /// <summary>
        /// 商户门店信息
        /// </summary>
        public class Store_Info
        {
            /// <summary>
            /// 详细地址
            /// 详细的商户门店地址
            /// 示例值：广东省深圳市南山区科技中一道10000号
            /// </summary>
            public string address { get; set; }

            /// <summary>
            /// 地区编码	
            /// 地区编码，详细请见省市区编号对照表。
            /// 示例值：440305
            /// </summary>
            public string area_code { get; set; }

            /// <summary>
            /// 门店名称
            /// 商户侧门店名称
            /// 示例值：腾讯大厦分店
            /// </summary>
            public string name { get; set; }

            /// <summary>
            /// 门店编号
            /// 商户侧门店编号
            /// 示例值：0001
            /// </summary>
            public string id { get; set; }
        }

        /// <summary>
        /// 结算信息
        /// </summary>
        public class Settle_Info
        {
            /// <summary>
            /// 是否指定分账
            /// </summary>
            public bool profit_sharing { get; set; }
        }
    }
}
