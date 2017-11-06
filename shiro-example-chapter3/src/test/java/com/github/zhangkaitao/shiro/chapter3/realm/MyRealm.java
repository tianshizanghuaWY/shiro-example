package com.github.zhangkaitao.shiro.chapter3.realm;

import com.github.zhangkaitao.shiro.chapter3.permission.BitPermission;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.authz.permission.WildcardPermission;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

/**
 * <p>User: Zhang Kaitao
 * <p>Date: 14-1-26
 * <p>Version: 1.0
 *
 * 认证信息、角色信息、权限信息  都由 Realm 来维护。
 */
public class MyRealm extends AuthorizingRealm {

    /*
     * 返回权限信息
     * 调用栈 :
     * SubObject.isPermitted
     *  ->SecurityManager.isPermitted
     *    -> AuthorizingRealm.isPermitted(PrincipalCollection principals, Permission permission)
     *       -> AuthorizingRealm.doGetAuthorizationInfo
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
        authorizationInfo.addRole("role1");
        authorizationInfo.addRole("role2");

        //自定义 Permission
        authorizationInfo.addObjectPermission(new BitPermission("+user1+10"));

        //通配符方式的Permission
        authorizationInfo.addObjectPermission(new WildcardPermission("user1:*"));

        authorizationInfo.addStringPermission("+user2+10");
        authorizationInfo.addStringPermission("user2:*");

        return authorizationInfo;
    }

    /*
     * 返回认证信息
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        String username = (String)token.getPrincipal();  //得到用户名
        String password = new String((char[])token.getCredentials()); //得到密码

        if(!"zhang".equals(username)) {
            throw new UnknownAccountException(); //如果用户名错误
        }
        if(!"123".equals(password)) {
            throw new IncorrectCredentialsException(); //如果密码错误
        }

        //如果身份认证验证成功，返回一个AuthenticationInfo实现；
        return new SimpleAuthenticationInfo(username, password, getName());
    }
}
