<?php decorate_with('layout_2col.php') ?>

<?php slot('sidebar') ?>

  <?php echo get_component('settings', 'menu') ?>

<?php end_slot() ?>

<?php slot('title') ?>

  <h1><?php echo __('Uploads settings') ?></h1>

<?php end_slot() ?>

<?php slot('content') ?>

  <?php echo $form->renderFormTag(url_for(
    ['module' => 'settings', 'action' => 'uploads']
  )) ?>

    <div id="content">

      <table class="table sticky-enabled">
        <thead>
          <tr>
            <th><?php echo __('Name')?></th>
            <th><?php echo __('Value')?></th>
          </tr>
        </thead>

        <tbody>

          <?php echo $form
            ->repository_quota
            ->label(__(
              'Default %1% upload limit (GB)',
              ['%1%' => strtolower(sfConfig::get('app_ui_label_repository'))]
            ))
            ->help(__(
                'Default %1% upload limit for a new %2%.  A value of &quot;0'
                . '&quot; (zero) disables file upload.  A value of &quot;-1'
                . '&quot; allows unlimited uploads',
                [
                  '%1%' => strtolower(sfConfig::get('app_ui_label_digitalobject')),
                  '%2%' => strtolower(sfConfig::get('app_ui_label_repository'))
                ]
              ))
            ->renderRow()
          ?>

          <?php echo $form
            ->upload_quota
            ->label(__('Total space available for uploads'))
            ->renderRow()
          ?>

          <?php echo $form
            ->explode_multipage_files
            ->label(__('Upload multi-page files as multiple descriptions'))
            ->renderRow()
          ?>

        </tbody>
      </table>

    </div>

    <section class="actions">
      <ul>
        <li>
          <input class="c-btn c-btn-submit" type="submit" value="<?php echo __('Save') ?>"/>
        </li>
      </ul>
    </section>

  </form>

<?php end_slot() ?>
