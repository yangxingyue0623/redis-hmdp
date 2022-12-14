package com.hmdp.service.impl;

import cn.hutool.core.bean.BeanUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.json.JSONUtil;
import com.hmdp.dto.Result;
import com.hmdp.entity.Shop;
import com.hmdp.entity.ShopType;
import com.hmdp.mapper.ShopTypeMapper;
import com.hmdp.service.IShopTypeService;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.ArrayList;
import java.util.List;

import static com.hmdp.utils.RedisConstants.CACHE_SHOPTYPE_KEY;
import static com.hmdp.utils.RedisConstants.CACHE_SHOP_KEY;

/**
 * <p>
 *  服务实现类
 * </p>
 */
@Service
public class ShopTypeServiceImpl extends ServiceImpl
        <ShopTypeMapper, ShopType> implements IShopTypeService {
    @Resource
    private StringRedisTemplate stringRedisTemplate;
    public Result  queryshopTypeList(){
        //展示所有的店铺信息
        String key =CACHE_SHOPTYPE_KEY ;
        //1.从redis查询商铺缓存
        // String shopJson = stringRedisTemplate.opsForValue().get(key);
        List<String> strshopTypeList = stringRedisTemplate.opsForList().range(key, 0, -1);
        ArrayList<ShopType> shopTypes = new ArrayList<>();
        //2.判断是否存在
        if (!strshopTypeList.isEmpty()){
            //3.存在直接返回

            for (String s:strshopTypeList) {
                ShopType shopType = JSONUtil.toBean(s, ShopType.class);
                shopTypes.add(shopType);
            }
            return Result.ok(shopTypes);
        }

        //4.不存在,查询数据库
        List<ShopType> typeList = query().orderByAsc("sort").list();
        //5.不存在直接返回错误
        if(typeList.isEmpty()){
            return Result.fail("不存在分类");
        }
        //6.存在写入rdis
        for (ShopType s:typeList) {
            String shopjson = JSONUtil.toJsonStr(s);
            strshopTypeList.add(shopjson);
        }
        stringRedisTemplate.opsForList().rightPushAll(key,strshopTypeList);

        return Result.ok(typeList);
    }


}
