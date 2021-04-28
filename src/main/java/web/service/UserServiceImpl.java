package web.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import web.Dao.RoleDao;
import web.Dao.UserDao;
import web.models.Role;
import web.models.User;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
public class UserServiceImpl implements UserService{

    private final BCryptPasswordEncoder passwordEncoder;

    private final RoleDao roleDao;

    private final UserDao userDao;

    public UserServiceImpl(UserDao userDao, RoleDao roleDao, BCryptPasswordEncoder passwordEncoder) {
        this.userDao = userDao;
        this.roleDao = roleDao;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public List<Role> getAllRoles() {
        List<Role> roles = new ArrayList<>();
        roles.add(roleDao.getById(1));
        roles.add(roleDao.getById(2));
        return  roles;
    }
    @Override
    public List<User> allUsers() {
        return userDao.allUsers();
    }

    @Override
    public void add(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userDao.add(user);
    }

    @Override
    public void delete(User user) {
        userDao.delete(user);
    }

    @Override
    public void update(User user, String[] roleList) {
        List<Role> set = new ArrayList<>();
        if (roleList != null){
            for (int i =0; i<roleList.length; i++) {
                if (!user.getRoles().contains(roleList[i])){
                    set.add(roleDao.getByName(roleList[i]));
                }
            }
            user.setRoles(set);
        }
        if (!userDao.getById(user.getId()).getPassword().equals(user.getPassword())) {
            user.setPassword(passwordEncoder.encode(user.getPassword()));
        }
        userDao.update(user);
    }

    @Override
    public User getById(int id) {
        return userDao.getById(id);
    }

    @Override
    public User getByName(String name) {
        return userDao.getByName(name);
    }

}
