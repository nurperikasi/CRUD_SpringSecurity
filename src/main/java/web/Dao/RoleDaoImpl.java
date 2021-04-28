package web.Dao;

import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import web.models.Role;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.TypedQuery;
import java.util.List;
import java.util.Set;

@Repository
@Transactional
public class RoleDaoImpl implements RoleDao {

    @PersistenceContext
    private EntityManager entityManager;

    public List<Role> getAllRoles() {
        return entityManager.createQuery("select r from Role r", Role.class).getResultList();
    }

    public  void add(Role role) {
        entityManager.merge(role);
    }

    public void update(Role role) {
        entityManager.remove(role);
    }

    @Transactional(readOnly = true)
    public Role getById(int id) {
        TypedQuery<Role> query = entityManager.createQuery("select r from Role r where r.id=:id", Role.class);
        query.setParameter("id", id);
        return query.getSingleResult();
    }

    @Transactional(readOnly = true)
    public Role getByName(String name) {
        TypedQuery<Role> query = entityManager.createQuery("select r from Role r where r.role=:name", Role.class);
        query.setParameter("name", name);
        return query.getResultList().get(0);
    }

    public void deleteRole(Role role) {
        entityManager.remove(role);
    }

    public void deleteRoles(Set<Role> roles) {
        for (Role role : roles) {
            entityManager.remove(role);
        }
    }

    @Override
    public Role getOne(Long aLong) {
        TypedQuery<Role> query = entityManager.createQuery("select r from Role r where r.id=:id", Role.class);
        query.setParameter("id", aLong);
        return query.getResultList().stream().findAny().orElse(null);
    }
}