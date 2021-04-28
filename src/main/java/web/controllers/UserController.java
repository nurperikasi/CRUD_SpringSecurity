package web.controllers;


import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import web.Dao.RoleDao;
import web.models.User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;
import web.service.UserService;

import java.util.List;

@Controller
@RequestMapping("/")
public class UserController {

    private final RoleDao roleDao;

    private final UserService userService;

    public UserController(RoleDao roleDao, UserService userService) {
        this.roleDao = roleDao;
        this.userService = userService;
    }

    @GetMapping("/admin")
    public ModelAndView admin(){
        ModelAndView modelAndView = new ModelAndView();
        modelAndView.setViewName("admin");

        Authentication loggedInUser = SecurityContextHolder.getContext().getAuthentication();
        String username = loggedInUser.getName();
        modelAndView.addObject("user", userService.getByName(username));

        List<User> list = userService.allUsers();
        modelAndView.addObject("allUsers", list);
        return modelAndView;
    }

    @GetMapping("/user")
    public ModelAndView user() {
        ModelAndView modelAndView = new ModelAndView();

        Authentication loggedInUser = SecurityContextHolder.getContext().getAuthentication();
        String username = loggedInUser.getName();
        modelAndView.addObject("user", userService.getByName(username));

        modelAndView.setViewName("user'sPage");
        return modelAndView;
    }

    @GetMapping("/update/{id}")
    public ModelAndView updatePage(@PathVariable("id") int id){
        ModelAndView modelAndView = new ModelAndView();
        modelAndView.addObject("user", userService.getById(id));
        modelAndView.addObject("roleList", userService.getAllRoles());
        modelAndView.setViewName("updatePage");
        return modelAndView;
    }

    @PostMapping("/update")
    public  ModelAndView updateUser(@ModelAttribute("user") User user,
                                    @RequestParam(value = "roles", required = false)String [] roleList){
        ModelAndView modelAndView = new ModelAndView();
        modelAndView.setViewName("redirect:/admin");
        userService.update(user, roleList);
        return modelAndView;
    }

    @GetMapping("/addPage")
    public ModelAndView addPage(){
        ModelAndView modelAndView = new ModelAndView();
        modelAndView.addObject("user", new User());
        modelAndView.addObject("roleList", userService.getAllRoles());
        modelAndView.setViewName("addPage");
        return modelAndView;
    }

    @PostMapping("/add")
    public ModelAndView addUser(@ModelAttribute("user") User user){
        ModelAndView modelAndView = new ModelAndView();
        modelAndView.setViewName("redirect:/admin");
        userService.add(user);
        return modelAndView;
    }

    @GetMapping("/delete/{id}")
    public ModelAndView deleteUser(@PathVariable("id") int id){
        ModelAndView modelAndView = new ModelAndView();
        User user = userService.getById(id);
        userService.delete(user);
        modelAndView.setViewName("redirect:/admin");
        return modelAndView;
    }
}
